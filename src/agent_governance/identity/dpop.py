# SPDX-License-Identifier: Apache-2.0
"""DPoP (RFC 9449): proof-of-possession for access tokens.

A DPoP proof is a short-lived JWT signed by the client's key, binding one HTTP request
(method + URI) and, when presenting an access token, that token's hash (``ath``). Tokens carry
``cnf.jkt`` = the key's RFC 7638 thumbprint, so a stolen token is useless without the key.
"""

from __future__ import annotations

import hashlib
import threading
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agent_governance.core import Clock, SystemClock, new_id
from agent_governance.crypto import b64url, ec_public_jwk, ec_public_key_from_jwk, jwk_thumbprint


class DpopError(ValueError):
    """The DPoP proof is missing, malformed, stale, replayed or bound to something else."""


def access_token_hash(token: str) -> str:
    return b64url(hashlib.sha256(token.encode("ascii")).digest())


def normalize_htu(uri: str) -> str:
    """Scheme and host lower-cased, query and fragment dropped (RFC 9449 section 4.3)."""
    parts = urlsplit(uri)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", ""))


def make_proof(
    key: ec.EllipticCurvePrivateKey,
    htm: str,
    htu: str,
    *,
    clock: Clock | None = None,
    access_token: str | None = None,
    jti: str | None = None,
) -> str:
    """Client side: build a DPoP proof for one request."""
    now = (clock or SystemClock()).now()
    claims: dict[str, Any] = {
        "jti": jti or new_id("dpop"),
        "htm": htm.upper(),
        "htu": htu,
        "iat": int(now.timestamp()),
    }
    if access_token is not None:
        claims["ath"] = access_token_hash(access_token)
    headers = {"typ": "dpop+jwt", "jwk": ec_public_jwk(key)}
    return jwt.encode(claims, key, algorithm="ES256", headers=headers)


class DpopVerifier:
    """Server side. The replay cache is per process; share it (e.g. Redis) across replicas."""

    def __init__(
        self,
        clock: Clock | None = None,
        max_age: timedelta = timedelta(seconds=60),
        leeway: timedelta = timedelta(seconds=5),
    ) -> None:
        self.clock = clock or SystemClock()
        self.max_age = max_age
        self.leeway = leeway
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def verify(
        self,
        proof: str | None,
        *,
        htm: str,
        htu: str,
        access_token: str | None = None,
        expected_jkt: str | None = None,
    ) -> str:
        """Validate ``proof`` for this request; return the proof key's thumbprint."""
        if not proof:
            raise DpopError("missing DPoP proof")
        try:
            header = jwt.get_unverified_header(proof)
        except jwt.PyJWTError as exc:
            raise DpopError(f"malformed DPoP proof: {exc}") from exc
        if header.get("typ") != "dpop+jwt" or header.get("alg") != "ES256":
            raise DpopError("DPoP proof must be typ dpop+jwt signed with ES256")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            raise DpopError("DPoP proof header lacks a public jwk")
        try:
            key = ec_public_key_from_jwk(jwk)
            claims = jwt.decode(
                proof,
                key,
                algorithms=["ES256"],
                # Times are checked below against the injected clock, not the wall clock.
                options={
                    "require": ["jti", "htm", "htu", "iat"],
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            raise DpopError(f"invalid DPoP proof: {exc}") from exc

        if str(claims["htm"]).upper() != htm.upper():
            raise DpopError("DPoP proof is for a different HTTP method")
        if normalize_htu(str(claims["htu"])) != normalize_htu(htu):
            raise DpopError("DPoP proof is for a different URI")
        now = self.clock.now().timestamp()
        iat = float(claims["iat"])
        if iat > now + self.leeway.total_seconds() or iat < now - self.max_age.total_seconds():
            raise DpopError("DPoP proof is outside the accepted time window")
        if access_token is not None and claims.get("ath") != access_token_hash(access_token):
            raise DpopError("DPoP proof is not bound to this access token")
        thumbprint = jwk_thumbprint(jwk)
        if expected_jkt is not None and thumbprint != expected_jkt:
            raise DpopError("DPoP key does not match the token's cnf.jkt")
        self._check_replay(str(claims["jti"]), now)
        return thumbprint

    def _check_replay(self, jti: str, now: float) -> None:
        horizon = now - self.max_age.total_seconds() - self.leeway.total_seconds()
        with self._lock:
            self._seen = {j: t for j, t in self._seen.items() if t > horizon}
            if jti in self._seen:
                raise DpopError("DPoP proof replayed")
            self._seen[jti] = now
