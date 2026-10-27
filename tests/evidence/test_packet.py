# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
from datetime import date
from typing import Any

import pytest

from agent_governance.core import FixedClock
from agent_governance.crypto import generate_ed25519_key, sign_document
from agent_governance.evidence.anchor import LocalTimestampAuthority
from agent_governance.evidence.packet import PacketBuilder, render_markdown, verify_packet
from agent_governance.evidence.record import EvidenceKind
from agent_governance.evidence.store import EvidenceStore

DAY = date(2026, 10, 27)
ACTOR: dict[str, str | None] = {"agent": "access-request@1.3.0", "delegator": "user:priya@acme"}


@pytest.fixture
def setup(clock: FixedClock) -> tuple[EvidenceStore, Any, LocalTimestampAuthority, dict[str, Any]]:
    store = EvidenceStore(clock=clock)
    store.append("acme", EvidenceKind.TOKEN_EXCHANGE, actor=ACTOR, verdict="issued")
    store.append(
        "acme",
        EvidenceKind.SOD_VERDICT,
        actor=ACTOR,
        verdict="deny",
        ruleset_version="starter-sap-2026.10",
    )
    store.append("acme", EvidenceKind.GATEWAY_DECISION, actor=ACTOR, verdict="deny")
    store.append(
        "acme", EvidenceKind.APPROVAL, actor=ACTOR, verdict="approved", approver="user:mark@acme"
    )
    tsa = LocalTimestampAuthority(generate_ed25519_key(), clock=clock)
    store.anchor_day("acme", DAY, tsa)
    key = generate_ed25519_key()
    packet = PacketBuilder(store, key, clock).build("acme", "AC-SOD-01", DAY, DAY)
    return store, key, tsa, packet


def test_packet_selects_control_records_and_verifies(setup: Any) -> None:
    _, key, tsa, packet = setup
    assert [r["kind"] for r in packet["records"]] == ["sod.verdict", "gateway.decision"]
    assert packet["ruleset_versions"] == ["starter-sap-2026.10"]
    assert len(packet["chains"]["2026-10-27"]["digests"]) == 4  # whole chain, digests only
    result = verify_packet(packet, signer_key=key.public_key(), tsa_key=tsa.public_key)
    assert result.ok, result.errors
    assert result.warnings == []


def test_altered_record_is_detected_even_if_resigned(setup: Any) -> None:
    _, key, tsa, packet = setup
    forged = copy.deepcopy(packet)
    forged["records"][0]["verdict"] = "allow"
    # an insider holding the packet signing key re-signs: the chain still exposes the edit
    body = {k: v for k, v in forged.items() if k != "signature"}
    forged["signature"] = sign_document(key, body)
    errors = verify_packet(forged, signer_key=key.public_key(), tsa_key=tsa.public_key).errors
    assert any("not in the packet's chain" in e for e in errors)


def test_untrusted_signer_and_bad_signature(setup: Any) -> None:
    _, key, tsa, packet = setup
    other = generate_ed25519_key()
    assert (
        "packet signed by an untrusted key"
        in verify_packet(packet, signer_key=other.public_key(), tsa_key=tsa.public_key).errors
    )
    tampered = {**packet, "tenant": "globex"}
    errors = verify_packet(tampered, signer_key=key.public_key(), tsa_key=tsa.public_key).errors
    assert "packet signature is invalid" in errors


def test_wrong_tsa_key_fails_anchor(setup: Any) -> None:
    _, key, _, packet = setup
    errors = verify_packet(
        packet, signer_key=key.public_key(), tsa_key=generate_ed25519_key().public_key()
    ).errors
    assert any("anchor signature is invalid" in e for e in errors)


def test_dropped_digest_breaks_chain(setup: Any) -> None:
    _, key, tsa, packet = setup
    forged = copy.deepcopy(packet)
    forged["chains"]["2026-10-27"]["digests"].pop(0)
    errors = verify_packet(forged, signer_key=key.public_key(), tsa_key=tsa.public_key).errors
    assert any("do not reproduce the chain root" in e for e in errors)


def test_unanchored_and_post_anchor_records_warn(clock: FixedClock) -> None:
    store = EvidenceStore(clock=clock)
    store.append("acme", EvidenceKind.SOD_VERDICT, actor=ACTOR, verdict="allow")
    key = generate_ed25519_key()
    packet = PacketBuilder(store, key, clock).build("acme", "AC-SOD-01", DAY, DAY)
    result = verify_packet(packet, signer_key=key.public_key(), tsa_key=None)
    assert result.ok
    assert result.warnings == ["2026-10-27: chain is not anchored"]

    tsa = LocalTimestampAuthority(generate_ed25519_key(), clock=clock)
    store.anchor_day("acme", DAY, tsa)
    store.append("acme", EvidenceKind.SOD_VERDICT, actor=ACTOR, verdict="allow")
    packet = PacketBuilder(store, key, clock).build("acme", "AC-SOD-01", DAY, DAY)
    result = verify_packet(packet, signer_key=key.public_key(), tsa_key=tsa.public_key)
    assert result.ok, result.errors
    assert result.warnings == ["2026-10-27: 1 records after the anchor"]


def test_unknown_control_and_bad_period(clock: FixedClock) -> None:
    builder = PacketBuilder(EvidenceStore(clock=clock), generate_ed25519_key(), clock)
    with pytest.raises(KeyError, match="unknown control"):
        builder.build("acme", "NOPE", DAY, DAY)
    with pytest.raises(ValueError, match="precedes"):
        builder.build("acme", "AC-SOD-01", DAY, date(2026, 10, 1))


def test_markdown_cover_sheet(setup: Any) -> None:
    text = render_markdown(setup[3])
    assert text.startswith("# Evidence packet: AC-SOD-01")
    assert "| deny | 2 |" in text
