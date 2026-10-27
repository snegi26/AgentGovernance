# SPDX-License-Identifier: Apache-2.0
"""Small primitives shared by every layer: time, canonical hashing and identifiers."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol


class Clock(Protocol):
    """Source of the current time. Inject a fixed clock in tests instead of patching."""

    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FixedClock:
    """A manually advanced clock for deterministic tests and demos."""

    def __init__(self, start: datetime) -> None:
        if start.tzinfo is None:
            raise ValueError("FixedClock requires a timezone-aware datetime")
        self._now = start
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, delta: timedelta) -> None:
        with self._lock:
            self._now += delta


def canonical_json(value: Any) -> bytes:
    """Serialise ``value`` deterministically (sorted keys, no whitespace, UTF-8).

    This is the JSON Canonicalization Scheme (RFC 8785) restricted to the value types the
    system emits: strings, integers, booleans, null, lists and objects. Floats are rejected
    because their textual form is the one place where naive serialisers disagree with JCS.
    """
    _reject_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("canonical_json does not accept floats; use integers or strings")
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _reject_floats(item)


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """``sha256:<hex>`` of the canonical JSON form of ``value``."""
    return sha256_hex(canonical_json(value))


_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_id(prefix: str) -> str:
    """A time-sortable identifier in ULID layout (48-bit ms timestamp + 80 random bits)."""
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return f"{prefix}_{''.join(reversed(chars))}"


def isoformat(ts: datetime) -> str:
    """UTC timestamp in the ``2026-10-27T14:03:11Z`` form used in evidence records."""
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
