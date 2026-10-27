# SPDX-License-Identifier: Apache-2.0
"""Reference issuers of *subject tokens*: a local IdP for humans and an event bus for triggers.

In production these are your IdP (Keycloak, Entra ID, Okta) and your event infrastructure;
the token service only needs their issuer name and public key. These classes exist so the
demo and the test suite exercise the same verification path production traffic takes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agent_governance.core import Clock, SystemClock, new_id
from agent_governance.crypto import generate_ec_key


class IssuerKind(StrEnum):
    IDP = "idp"
    EVENT_BUS = "event_bus"


@dataclass(frozen=True, slots=True)
class TrustedIssuer:
    issuer: str
    kind: IssuerKind
    public_key: ec.EllipticCurvePublicKey


class _LocalIssuer:
    kind: IssuerKind

    def __init__(
        self, issuer: str, clock: Clock | None = None, key: ec.EllipticCurvePrivateKey | None = None
    ) -> None:
        self.issuer = issuer
        self.clock = clock or SystemClock()
        self._key = key or generate_ec_key()

    @property
    def trusted(self) -> TrustedIssuer:
        return TrustedIssuer(self.issuer, self.kind, self._key.public_key())

    def _issue(
        self, subject: str, audience: str, lifetime: timedelta, extra: dict[str, Any]
    ) -> str:
        now = self.clock.now()
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + lifetime).timestamp()),
            "jti": new_id("sub"),
            **extra,
        }
        return jwt.encode(claims, self._key, algorithm="ES256")


class LocalIdentityProvider(_LocalIssuer):
    kind = IssuerKind.IDP

    def issue_user_token(
        self, user_id: str, audience: str, lifetime: timedelta = timedelta(minutes=10)
    ) -> str:
        return self._issue(user_id, audience, lifetime, {})


class LocalEventBus(_LocalIssuer):
    kind = IssuerKind.EVENT_BUS

    def issue_trigger_token(
        self,
        trigger_id: str,
        event_id: str,
        audience: str,
        lifetime: timedelta = timedelta(minutes=5),
    ) -> str:
        return self._issue(f"trigger:{trigger_id}", audience, lifetime, {"event_id": event_id})


def make_client_assertion(
    key: ec.EllipticCurvePrivateKey,
    agent_principal: str,
    audience: str,
    clock: Clock | None = None,
) -> str:
    """``private_key_jwt`` client assertion an agent uses as its RFC 8693 ``actor_token``."""
    now = (clock or SystemClock()).now()
    claims = {
        "iss": agent_principal,
        "sub": agent_principal,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "jti": new_id("ca"),
    }
    return jwt.encode(claims, key, algorithm="ES256")
