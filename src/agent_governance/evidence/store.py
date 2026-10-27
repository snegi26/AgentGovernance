# SPDX-License-Identifier: Apache-2.0
"""Append-only, hash-chained evidence store (SQLite reference backend).

The store enforces append-only at two levels: the Python API has no update or delete, and
database triggers abort any ``UPDATE`` or ``DELETE`` issued directly against the tables. The
chain makes anything that bypasses both (editing the file) detectable by :meth:`verify`, and
the anchored daily root makes rewriting a whole day detectable too.

Production deployments mirror records to object storage with WORM retention; that mirror
consumes :meth:`EvidenceStore.records` and is outside this reference implementation.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol

from agent_governance.core import Clock, SystemClock, isoformat, new_id
from agent_governance.evidence.anchor import TimestampAuthority, TimestampToken
from agent_governance.evidence.record import EvidenceRecord, genesis_hash, link_hash


class EvidenceUnavailableError(RuntimeError):
    """The evidence store cannot accept writes. Callers must fail closed."""


class EvidenceSink(Protocol):
    """What the gateway needs from the evidence store: a durable, chained append."""

    def append(
        self,
        tenant: str,
        kind: str,
        *,
        actor: Mapping[str, str | None],
        verdict: str,
        **fields: Any,
    ) -> EvidenceRecord: ...


@dataclass(frozen=True, slots=True)
class ChainVerification:
    tenant: str
    day: str
    ok: bool
    count: int
    root: str
    first_bad_record: str | None = None
    error: str | None = None


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS evidence (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT NOT NULL,
    day TEXT NOT NULL,
    record_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    hash TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_evidence_chain ON evidence(tenant, day, seq);
CREATE TABLE IF NOT EXISTS anchor (
    tenant TEXT NOT NULL,
    day TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    root TEXT NOT NULL,
    token TEXT NOT NULL,
    PRIMARY KEY (tenant, day, record_count)
);
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS anchor_no_update BEFORE UPDATE ON anchor
BEGIN SELECT RAISE(ABORT, 'anchors are append-only'); END;
CREATE TRIGGER IF NOT EXISTS anchor_no_delete BEFORE DELETE ON anchor
BEGIN SELECT RAISE(ABORT, 'anchors are append-only'); END;
"""


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    tenant: str
    day: str
    record_count: int
    root: str
    token: TimestampToken


class EvidenceStore:
    def __init__(self, path: str = ":memory:", clock: Clock | None = None) -> None:
        self.path = path
        self.clock = clock or SystemClock()
        self._lock = threading.Lock()
        try:
            self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            self._db.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise EvidenceUnavailableError(str(exc)) from exc

    # -- writes ---------------------------------------------------------------------------

    def append(
        self,
        tenant: str,
        kind: str,
        *,
        actor: Mapping[str, str | None],
        verdict: str,
        **fields: Any,
    ) -> EvidenceRecord:
        ts = isoformat(self.clock.now())
        day = ts[:10]
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                row = self._db.execute(
                    "SELECT hash FROM evidence WHERE tenant=? AND day=? ORDER BY seq DESC LIMIT 1",
                    (tenant, day),
                ).fetchone()
                prev = row[0] if row else genesis_hash(tenant, day)
                unsigned = EvidenceRecord(
                    record_id=new_id("ev"),
                    ts=ts,
                    tenant=tenant,
                    kind=str(kind),
                    actor=actor,
                    verdict=verdict,
                    prev_hash=prev,
                    **fields,
                )
                record = EvidenceRecord.from_dict(
                    {**unsigned.to_dict(), "hash": link_hash(prev, unsigned.content_digest())}
                )
                self._db.execute(
                    "INSERT INTO evidence(tenant, day, record_id, kind, hash, body)"
                    " VALUES (?,?,?,?,?,?)",
                    (
                        tenant,
                        day,
                        record.record_id,
                        record.kind,
                        record.hash,
                        json.dumps(record.to_dict()),
                    ),
                )
                self._db.execute("COMMIT")
            except sqlite3.Error as exc:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise EvidenceUnavailableError(str(exc)) from exc
        return record

    def anchor_day(self, tenant: str, day: date | str, tsa: TimestampAuthority) -> AnchorRecord:
        """Timestamp the current root of ``tenant``'s chain for ``day``."""
        day_s = day if isinstance(day, str) else day.isoformat()
        records = self.records(tenant, day=day_s)
        if not records:
            raise ValueError(f"no evidence for {tenant} on {day_s}")
        root = records[-1].hash
        token = tsa.timestamp(root)
        anchor = AnchorRecord(tenant, day_s, len(records), root, token)
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO anchor VALUES (?,?,?,?,?)",
                (tenant, day_s, len(records), root, json.dumps(token.to_dict())),
            )
        return anchor

    # -- reads ----------------------------------------------------------------------------

    def get(self, record_id: str) -> EvidenceRecord:
        with self._lock:
            row = self._db.execute(
                "SELECT body FROM evidence WHERE record_id=?", (record_id,)
            ).fetchone()
        if row is None:
            raise KeyError(record_id)
        return EvidenceRecord.from_dict(json.loads(row[0]))

    def records(
        self,
        tenant: str,
        *,
        day: str | None = None,
        start: date | None = None,
        end: date | None = None,
        kinds: Iterable[str] | None = None,
    ) -> list[EvidenceRecord]:
        sql = "SELECT body FROM evidence WHERE tenant=?"
        params: list[Any] = [tenant]
        if day is not None:
            sql += " AND day=?"
            params.append(day)
        if start is not None:
            sql += " AND day>=?"
            params.append(start.isoformat())
        if end is not None:
            sql += " AND day<=?"
            params.append(end.isoformat())
        kind_list = list(kinds) if kinds is not None else None
        if kind_list is not None:
            sql += f" AND kind IN ({','.join('?' for _ in kind_list)})"
            params += kind_list
        sql += " ORDER BY seq"
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [EvidenceRecord.from_dict(json.loads(r[0])) for r in rows]

    def days(self, tenant: str) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT day FROM evidence WHERE tenant=? ORDER BY day", (tenant,)
            ).fetchall()
        return [r[0] for r in rows]

    def anchors(self, tenant: str, day: str) -> list[AnchorRecord]:
        with self._lock:
            rows = self._db.execute(
                "SELECT record_count, root, token FROM anchor"
                " WHERE tenant=? AND day=? ORDER BY record_count",
                (tenant, day),
            ).fetchall()
        return [
            AnchorRecord(tenant, day, r[0], r[1], TimestampToken.from_dict(json.loads(r[2])))
            for r in rows
        ]

    def verify(self, tenant: str, day: date | str) -> ChainVerification:
        """Recompute the chain for one tenant-day; report the first record that does not link."""
        day_s = day if isinstance(day, str) else day.isoformat()
        with self._lock:
            rows = self._db.execute(
                "SELECT record_id, hash, body FROM evidence WHERE tenant=? AND day=? ORDER BY seq",
                (tenant, day_s),
            ).fetchall()
        prev = genesis_hash(tenant, day_s)
        for count, (record_id, stored_hash, body) in enumerate(rows):
            try:
                record = EvidenceRecord.from_dict(json.loads(body))
            except (ValueError, TypeError) as exc:
                return ChainVerification(
                    tenant, day_s, False, count, prev, record_id, f"unreadable: {exc}"
                )
            expected = link_hash(prev, record.content_digest())
            if record.prev_hash != prev or record.hash != expected or stored_hash != expected:
                return ChainVerification(
                    tenant, day_s, False, count, prev, record_id, "hash mismatch"
                )
            prev = expected
        anchors = self.anchors(tenant, day_s)
        for anchor in anchors:
            if anchor.record_count > len(rows):
                return ChainVerification(
                    tenant, day_s, False, len(rows), prev, None, "anchored records are missing"
                )
            if json.loads(rows[anchor.record_count - 1][2])["hash"] != anchor.root:
                return ChainVerification(
                    tenant,
                    day_s,
                    False,
                    len(rows),
                    prev,
                    rows[anchor.record_count - 1][0],
                    "chain does not match anchored root",
                )
        return ChainVerification(tenant, day_s, True, len(rows), prev)
