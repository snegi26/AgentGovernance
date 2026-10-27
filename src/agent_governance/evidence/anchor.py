# SPDX-License-Identifier: Apache-2.0
"""Anchoring daily chain roots to a timestamping authority.

Production deployments anchor to an external RFC 3161 TSA by implementing
:class:`TimestampAuthority`. :class:`LocalTimestampAuthority` is the reference implementation:
an Ed25519-signed token over ``(digest, gen_time, serial)`` that verifies offline.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, replace
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_governance.core import Clock, SystemClock, isoformat
from agent_governance.crypto import (
    ed25519_key_id,
    ed25519_public_b64,
    sign_document,
    verify_document,
)


@dataclass(frozen=True, slots=True)
class TimestampToken:
    tsa: str
    key_id: str
    digest: str
    gen_time: str
    serial: int
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "tsa": self.tsa,
            "key_id": self.key_id,
            "digest": self.digest,
            "gen_time": self.gen_time,
            "serial": self.serial,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimestampToken:
        return cls(**data)


class TimestampAuthority(Protocol):
    name: str

    def timestamp(self, digest: str) -> TimestampToken: ...


class LocalTimestampAuthority:
    def __init__(
        self,
        key: Ed25519PrivateKey,
        name: str = "local-tsa",
        clock: Clock | None = None,
    ) -> None:
        self.name = name
        self._key = key
        self._clock = clock or SystemClock()
        self._serial = itertools.count(1)
        self._lock = threading.Lock()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    @property
    def public_key_b64(self) -> str:
        return ed25519_public_b64(self._key)

    def timestamp(self, digest: str) -> TimestampToken:
        with self._lock:
            serial = next(self._serial)
        draft = TimestampToken(
            tsa=self.name,
            key_id=ed25519_key_id(self._key),
            digest=digest,
            gen_time=isoformat(self._clock.now()),
            serial=serial,
            signature="",
        )
        return replace(draft, signature=sign_document(self._key, draft.signed_fields()))


def verify_timestamp(token: TimestampToken, public_key: Ed25519PublicKey) -> bool:
    if token.key_id != ed25519_key_id(public_key):
        return False
    return verify_document(public_key, token.signed_fields(), token.signature)
