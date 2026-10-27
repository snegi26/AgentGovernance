# SPDX-License-Identifier: Apache-2.0
"""Key handling shared by tokens, DPoP, approvals, anchors and packets.

* EC P-256 (ES256) keys sign access tokens and DPoP proofs, and are identified by their
  RFC 7638 JWK thumbprint.
* Ed25519 keys sign approvals, timestamp tokens and evidence packets.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_governance.core import canonical_json


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --- EC P-256 -------------------------------------------------------------------------------


def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def ec_public_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> dict[str, str]:
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    numbers = public.public_numbers()
    if not isinstance(public.curve, ec.SECP256R1):
        raise ValueError("only P-256 keys are supported")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
    }


def ec_public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 JWKs are supported")
    if "d" in jwk:
        raise ValueError("JWK contains private key material")
    x = int.from_bytes(b64url_decode(str(jwk["x"])), "big")
    y = int.from_bytes(b64url_decode(str(jwk["y"])), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint (SHA-256, base64url) of an EC public JWK."""
    required = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    return b64url(
        hashlib.sha256(
            json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
        ).digest()
    )


# --- Ed25519 --------------------------------------------------------------------------------


def generate_ed25519_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def ed25519_public_b64(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return b64url(public.public_bytes(Encoding.Raw, PublicFormat.Raw))


def ed25519_public_from_b64(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64url_decode(text))


def ed25519_key_id(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    raw = b64url_decode(ed25519_public_b64(key))
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def sign_document(key: Ed25519PrivateKey, document: dict[str, Any]) -> str:
    """Detached Ed25519 signature over the canonical JSON form of ``document``."""
    return b64url(key.sign(canonical_json(document)))


def verify_document(public: Ed25519PublicKey, document: dict[str, Any], signature: str) -> bool:
    try:
        public.verify(b64url_decode(signature), canonical_json(document))
    except (InvalidSignature, ValueError):
        return False
    return True
