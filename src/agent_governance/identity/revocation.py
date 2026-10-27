# SPDX-License-Identifier: Apache-2.0
"""Token revocation list checked by the gateway on every call."""

from __future__ import annotations

import threading
from datetime import datetime


class RevocationList:
    """Revokes single tokens by ``jti`` or every token a subject was issued before a cutoff.

    Entries for single tokens can be dropped once the token would have expired anyway; the
    5-minute token lifetime keeps the list small.
    """

    def __init__(self) -> None:
        self._jtis: dict[str, int] = {}
        self._subjects: dict[str, int] = {}
        self._lock = threading.Lock()

    def revoke_token(self, jti: str, exp: int) -> None:
        with self._lock:
            self._jtis[jti] = exp

    def revoke_subject(self, subject: str, issued_before: datetime) -> None:
        """Revoke every token for ``subject`` issued at or before ``issued_before``."""
        cutoff = int(issued_before.timestamp())
        with self._lock:
            self._subjects[subject] = max(cutoff, self._subjects.get(subject, cutoff))

    def is_revoked(self, *, jti: str, subject: str, iat: int) -> bool:
        with self._lock:
            if jti in self._jtis:
                return True
            cutoff = self._subjects.get(subject)
            return cutoff is not None and iat <= cutoff

    def purge(self, now: datetime) -> None:
        current = int(now.timestamp())
        with self._lock:
            self._jtis = {j: exp for j, exp in self._jtis.items() if exp > current}
