# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from agent_governance.core import FixedClock
from agent_governance.crypto import generate_ed25519_key
from agent_governance.evidence.anchor import LocalTimestampAuthority, verify_timestamp
from agent_governance.evidence.record import EvidenceKind, genesis_hash, link_hash
from agent_governance.evidence.store import EvidenceStore, EvidenceUnavailableError

ACTOR: dict[str, str | None] = {"agent": "access-request@1.3.0", "delegator": "user:priya@acme"}


def _fill(store: EvidenceStore, n: int, tenant: str = "acme") -> None:
    for i in range(n):
        store.append(
            tenant, EvidenceKind.GATEWAY_DECISION, actor=ACTOR, verdict="allow", details={"i": i}
        )


def test_records_link_from_genesis(clock: FixedClock) -> None:
    store = EvidenceStore(clock=clock)
    first = store.append(
        "acme", EvidenceKind.SOD_VERDICT, actor=ACTOR, verdict="deny", ruleset_version="r1"
    )
    second = store.append("acme", EvidenceKind.GATEWAY_DECISION, actor=ACTOR, verdict="deny")
    assert first.prev_hash == genesis_hash("acme", "2026-10-27")
    assert first.hash == link_hash(first.prev_hash, first.content_digest())
    assert second.prev_hash == first.hash
    assert store.verify("acme", "2026-10-27").ok
    assert store.get(first.record_id) == first


def test_chains_are_per_tenant_and_per_day(clock: FixedClock) -> None:
    store = EvidenceStore(clock=clock)
    a = store.append("acme", "approval", actor=ACTOR, verdict="approved")
    b = store.append("globex", "approval", actor=ACTOR, verdict="approved")
    clock.advance(timedelta(days=1))
    c = store.append("acme", "approval", actor=ACTOR, verdict="approved")
    assert a.prev_hash == genesis_hash("acme", "2026-10-27")
    assert b.prev_hash == genesis_hash("globex", "2026-10-27")
    assert c.prev_hash == genesis_hash("acme", "2026-10-28")
    assert store.days("acme") == ["2026-10-27", "2026-10-28"]


@pytest.mark.parametrize("statement", ["UPDATE evidence SET kind='x'", "DELETE FROM evidence"])
def test_database_rejects_update_and_delete(
    tmp_path: Path, clock: FixedClock, statement: str
) -> None:
    path = str(tmp_path / "ev.db")
    store = EvidenceStore(path, clock)
    _fill(store, 2)
    db = sqlite3.connect(path)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        db.execute(statement)


def _tamper(path: str, seq: int, mutate: str) -> None:
    """Simulate an admin who drops the triggers and edits a record body in place."""
    db = sqlite3.connect(path)
    db.execute("DROP TRIGGER evidence_no_update")
    body = json.loads(db.execute("SELECT body FROM evidence WHERE seq=?", (seq,)).fetchone()[0])
    if mutate == "verdict":
        body["verdict"] = "tampered"
    elif mutate == "rehash":
        # forge verdict *and* recompute this record's own hash; the next link still breaks
        from agent_governance.evidence.record import EvidenceRecord

        body["verdict"] = "tampered"
        rec = EvidenceRecord.from_dict(body)
        body["hash"] = link_hash(rec.prev_hash, rec.content_digest())
        db.execute("UPDATE evidence SET hash=? WHERE seq=?", (body["hash"], seq))
    db.execute("UPDATE evidence SET body=? WHERE seq=?", (json.dumps(body), seq))
    db.commit()


@pytest.mark.parametrize("mutate", ["verdict", "rehash"])
def test_verify_detects_tampering(tmp_path: Path, clock: FixedClock, mutate: str) -> None:
    path = str(tmp_path / "ev.db")
    store = EvidenceStore(path, clock)
    _fill(store, 3)
    victim = store.records("acme")[1]
    _tamper(path, 2, mutate)
    result = EvidenceStore(path, clock).verify("acme", "2026-10-27")
    assert not result.ok
    expected_bad = victim.record_id if mutate == "verdict" else store.records("acme")[2].record_id
    assert result.first_bad_record == expected_bad


def test_anchor_detects_consistent_rewrite_of_a_whole_day(
    tmp_path: Path, clock: FixedClock
) -> None:
    path = str(tmp_path / "ev.db")
    store = EvidenceStore(path, clock)
    tsa = LocalTimestampAuthority(generate_ed25519_key(), clock=clock)
    _fill(store, 2)
    anchor = store.anchor_day("acme", "2026-10-27", tsa)
    assert verify_timestamp(anchor.token, tsa.public_key)
    # attacker deletes the day and writes a fully consistent replacement chain
    db = sqlite3.connect(path)
    db.execute("DROP TRIGGER evidence_no_delete")
    db.execute("DELETE FROM evidence")
    db.commit()
    forged = EvidenceStore(path, clock)
    _fill(forged, 2)
    result = forged.verify("acme", "2026-10-27")
    assert not result.ok
    assert result.error == "chain does not match anchored root"


def test_anchor_requires_records(clock: FixedClock) -> None:
    store = EvidenceStore(clock=clock)
    with pytest.raises(ValueError, match="no evidence"):
        store.anchor_day("acme", "2026-10-27", LocalTimestampAuthority(generate_ed25519_key()))


def test_verify_empty_day_is_ok(clock: FixedClock) -> None:
    result = EvidenceStore(clock=clock).verify("acme", "2026-10-27")
    assert result.ok
    assert result.count == 0


def test_unwritable_store_raises_unavailable(tmp_path: Path) -> None:
    with pytest.raises(EvidenceUnavailableError):
        EvidenceStore(str(tmp_path / "missing-dir" / "ev.db"))


def test_get_unknown_record(clock: FixedClock) -> None:
    with pytest.raises(KeyError):
        EvidenceStore(clock=clock).get("ev_nope")


def test_failed_append_does_not_poison_the_connection(clock: FixedClock) -> None:
    store = EvidenceStore(clock=clock)
    with pytest.raises(TypeError):
        store.append("acme", "approval", actor=ACTOR, verdict="x", not_a_field=1)
    with pytest.raises(TypeError):
        store.append("acme", "approval", actor=ACTOR, verdict="x", details={"n": float("nan")})
    store.append("acme", "approval", actor=ACTOR, verdict="ok")
    assert store.verify("acme", "2026-10-27").ok


def test_floats_are_accepted_in_details(clock: FixedClock) -> None:
    store = EvidenceStore(clock=clock)
    record = store.append(
        "acme", "approval", actor=ACTOR, verdict="ok", details={"amount": 48250.5}
    )
    assert store.get(record.record_id).details == {"amount": 48250.5}
    assert store.verify("acme", "2026-10-27").ok


def test_anchor_token_is_checked_not_just_the_root_column(
    tmp_path: Path, clock: FixedClock
) -> None:
    path = str(tmp_path / "ev.db")
    store = EvidenceStore(path, clock)
    tsa = LocalTimestampAuthority(generate_ed25519_key(), clock=clock)
    _fill(store, 2)
    store.anchor_day("acme", "2026-10-27", tsa)
    assert store.verify("acme", "2026-10-27", tsa.public_key).ok
    # rewrite the day consistently AND repoint the anchor's root column; the old token stays
    db = sqlite3.connect(path)
    db.execute("DROP TRIGGER evidence_no_delete")
    db.execute("DELETE FROM evidence")
    db.commit()
    forged = EvidenceStore(path, clock)  # reopening re-creates the append-only triggers
    _fill(forged, 2)
    new_root = forged.records("acme")[-1].hash
    db.execute("DROP TRIGGER anchor_no_update")
    db.execute("UPDATE anchor SET root=?", (new_root,))
    db.commit()
    result = EvidenceStore(path, clock).verify("acme", "2026-10-27")
    assert not result.ok
    assert result.error == "anchor token does not verify"
    other_tsa = generate_ed25519_key().public_key()
    assert (
        EvidenceStore(path, clock).verify("acme", "2026-10-27", other_tsa).error
        == "anchor token does not verify"
    )
