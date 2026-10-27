# SPDX-License-Identifier: Apache-2.0
"""Auditor-facing evidence packets, assembled from records only (never from model output).

A packet holds, for one control and period:

* the selected decision records, in full;
* per day, the ordered content digests of *every* record in the chain, the chain root and the
  anchor token, so an auditor can recompute the chain and check the anchor without seeing
  records outside the control;
* the rule-set versions in force, and a summary by verdict;
* an Ed25519 signature over the canonical JSON of everything above.

:func:`verify_packet` checks all of this offline.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agent_governance.core import Clock, SystemClock, isoformat
from agent_governance.crypto import (
    ed25519_key_id,
    ed25519_public_b64,
    sign_document,
    verify_document,
)
from agent_governance.evidence.anchor import TimestampToken, verify_timestamp
from agent_governance.evidence.record import EvidenceKind, EvidenceRecord, genesis_hash, link_hash
from agent_governance.evidence.store import EvidenceStore

PACKET_VERSION = "1"


@dataclass(frozen=True, slots=True)
class Control:
    control_id: str
    title: str
    kinds: tuple[str, ...]
    frameworks: tuple[str, ...] = ()


#: Starter control catalogue. Framework mappings are indicative; confirm them with your auditor.
CONTROLS: dict[str, Control] = {
    c.control_id: c
    for c in (
        Control(
            "AC-SOD-01",
            "Segregation of duties is enforced on every agent write",
            (EvidenceKind.SOD_VERDICT, EvidenceKind.GATEWAY_DECISION),
            ("SOX ITGC: logical access", "ISO/IEC 27001:2022 A.5.3"),
        ),
        Control(
            "AC-APR-01",
            "High-risk writes are approved by named humans before execution",
            (EvidenceKind.APPROVAL, EvidenceKind.GATEWAY_DECISION),
            ("SOX ITGC: change and access approval", "ISO/IEC 27001:2022 A.5.18"),
        ),
        Control(
            "AC-ID-01",
            "Agents act only through delegated, short-lived, sender-constrained tokens",
            (
                EvidenceKind.TOKEN_EXCHANGE,
                EvidenceKind.GATEWAY_DECISION,
                EvidenceKind.REGISTRY_CHANGE,
            ),
            ("ISO/IEC 27001:2022 A.5.16-A.5.17", "ISO/IEC 42001:2023 A.6"),
        ),
    )
}


class PacketBuilder:
    def __init__(
        self,
        store: EvidenceStore,
        signing_key: Ed25519PrivateKey,
        clock: Clock | None = None,
    ) -> None:
        self.store = store
        self._key = signing_key
        self.clock = clock or SystemClock()

    def build(self, tenant: str, control_id: str, start: date, end: date) -> dict[str, Any]:
        control = CONTROLS.get(control_id)
        if control is None:
            raise KeyError(f"unknown control {control_id!r}; known: {sorted(CONTROLS)}")
        if end < start:
            raise ValueError("period end precedes start")
        selected = self.store.records(tenant, start=start, end=end, kinds=control.kinds)
        chains: dict[str, Any] = {}
        for day in sorted({r.day for r in selected}):
            day_records = self.store.records(tenant, day=day)
            anchors = self.store.anchors(tenant, day)
            latest = anchors[-1] if anchors else None
            chains[day] = {
                "genesis": genesis_hash(tenant, day),
                "digests": [r.content_digest() for r in day_records],
                "root": day_records[-1].hash,
                "anchor": (
                    {"record_count": latest.record_count, "token": latest.token.to_dict()}
                    if latest
                    else None
                ),
            }
        body: dict[str, Any] = {
            "packet_version": PACKET_VERSION,
            "tenant": tenant,
            "control": {
                "id": control.control_id,
                "title": control.title,
                "frameworks": list(control.frameworks),
            },
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "generated_at": isoformat(self.clock.now()),
            "ruleset_versions": sorted({r.ruleset_version for r in selected if r.ruleset_version}),
            "summary": {
                "records": len(selected),
                "by_kind": dict(sorted(Counter(r.kind for r in selected).items())),
                "by_verdict": dict(sorted(Counter(r.verdict for r in selected).items())),
                "approvers": sorted({r.approver for r in selected if r.approver}),
            },
            "records": [r.to_dict() for r in selected],
            "chains": chains,
            "signer": {
                "key_id": ed25519_key_id(self._key),
                "public_key": ed25519_public_b64(self._key),
            },
        }
        return {**body, "signature": sign_document(self._key, body)}


@dataclass
class PacketVerification:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def verify_packet(
    packet: dict[str, Any],
    *,
    signer_key: Ed25519PublicKey,
    tsa_key: Ed25519PublicKey | None,
) -> PacketVerification:
    """Verify signature, chains, anchors and record inclusion. Keys must come from the auditor's
    trust store, never from the packet itself."""
    result = PacketVerification()
    body = {k: v for k, v in packet.items() if k != "signature"}
    if packet.get("signer", {}).get("key_id") != ed25519_key_id(signer_key):
        result.errors.append("packet signed by an untrusted key")
    if not verify_document(signer_key, body, str(packet.get("signature", ""))):
        result.errors.append("packet signature is invalid")

    tenant = str(packet.get("tenant", ""))
    positions: dict[str, dict[str, int]] = {}
    hashes: dict[str, list[str]] = {}
    for day, chain in packet.get("chains", {}).items():
        if chain["genesis"] != genesis_hash(tenant, day):
            result.errors.append(f"{day}: wrong genesis")
        running = [chain["genesis"]]
        for d in chain["digests"]:
            running.append(link_hash(running[-1], d))
        hashes[day] = running
        positions[day] = {d: i for i, d in enumerate(chain["digests"])}
        if running[-1] != chain["root"]:
            result.errors.append(f"{day}: digests do not reproduce the chain root")
        anchor = chain.get("anchor")
        if anchor is None:
            result.warnings.append(f"{day}: chain is not anchored")
            continue
        token = TimestampToken.from_dict(anchor["token"])
        count = int(anchor["record_count"])
        if tsa_key is None:
            result.warnings.append(f"{day}: no TSA key supplied; anchor not checked")
        elif not verify_timestamp(token, tsa_key):
            result.errors.append(f"{day}: anchor signature is invalid")
        if not 0 < count < len(running) or token.digest != running[count]:
            result.errors.append(f"{day}: anchor does not match the chain")
        elif count < len(chain["digests"]):
            result.warnings.append(
                f"{day}: {len(chain['digests']) - count} records after the anchor"
            )

    for raw in packet.get("records", []):
        record = EvidenceRecord.from_dict(raw)
        day_positions = positions.get(record.day)
        index = day_positions.get(record.content_digest()) if day_positions else None
        if index is None:
            result.errors.append(f"{record.record_id}: not in the packet's chain (altered?)")
            continue
        if (
            record.prev_hash != hashes[record.day][index]
            or record.hash != hashes[record.day][index + 1]
        ):
            result.errors.append(f"{record.record_id}: chain links do not match")
    return result


def render_markdown(packet: dict[str, Any]) -> str:
    """A human-readable cover sheet for a packet. The JSON bundle remains the evidence."""
    control = packet["control"]
    summary = packet["summary"]
    lines = [
        f"# Evidence packet: {control['id']}",
        "",
        f"**Control:** {control['title']}  ",
        f"**Tenant:** {packet['tenant']}  ",
        f"**Period:** {packet['period']['start']} to {packet['period']['end']}  ",
        f"**Generated:** {packet['generated_at']}  ",
        f"**Signer:** `{packet['signer']['key_id']}`",
        "",
        f"Frameworks (indicative): {', '.join(control['frameworks']) or 'none'}",
        "",
        "## Summary",
        "",
        f"- Records: {summary['records']}",
        f"- Rule-set versions: {', '.join(packet['ruleset_versions']) or 'n/a'}",
        f"- Approvers: {', '.join(summary['approvers']) or 'none'}",
        "",
        "| Verdict | Count |",
        "| --- | --- |",
        *(f"| {k} | {v} |" for k, v in summary["by_verdict"].items()),
        "",
        "## Chains",
        "",
        "| Day | Records | Root | Anchored |",
        "| --- | --- | --- | --- |",
    ]
    for day, chain in packet["chains"].items():
        anchored = "yes" if chain["anchor"] else "no"
        lines.append(f"| {day} | {len(chain['digests'])} | `{chain['root'][:23]}…` | {anchored} |")
    lines += [
        "",
        "## Decisions",
        "",
        "| Time | Kind | Agent | Delegator | Verdict | Approver |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in packet["records"]:
        agent = r["actor"].get("agent") or ""
        delegator = r["actor"].get("delegator") or ""
        lines.append(
            f"| {r['ts']} | {r['kind']} | {agent} | {delegator} "
            f"| {r['verdict']} | {r['approver'] or ''} |"
        )
    return "\n".join(lines) + "\n"
