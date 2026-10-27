# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import statistics
import time
from collections.abc import Mapping
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from agent_governance.approval.tiers import ApprovalTier, ApproverRole
from agent_governance.demo.estate import DemoEstate
from agent_governance.evidence.store import EvidenceUnavailableError
from agent_governance.gateway.gateway import ToolCall, Verdict
from agent_governance.model import Mitigation, PrincipalStatus
from agent_governance.policy.engine import PolicyEngineError

PRIYA = "user:priya@acme"


def _approve(
    estate: DemoEstate, task_id: str | None, *pairs: tuple[str, ApproverRole]
) -> list[str]:
    return [estate.runtime.approvals.approve(task_id or "", who, role) for who, role in pairs]


# --- happy paths and approval tiers ---------------------------------------------------------


def test_low_risk_request_goes_to_line_manager_then_executes(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    args = {
        "roles": ["Z_VENDOR_DISPLAY"],
        "end_date": "2026-11-15",
        "justification": "vendor look-ups",
    }
    parked = agent.call(token, "iag.submit_request", args)
    assert parked.verdict is Verdict.REQUIRE_APPROVAL
    assert parked.tier is ApprovalTier.LOW_RISK_WRITE
    approvals = _approve(
        estate, parked.approval_task_id, ("user:mark@acme", ApproverRole.LINE_MANAGER)
    )
    done = agent.call(token, "iag.submit_request", args, approvals=approvals)
    assert done.verdict is Verdict.ALLOW
    assert done.result is not None
    assert done.result["status"] == "submitted"
    record = estate.runtime.evidence.get(done.evidence_id or "")
    assert record.approver == "user:mark@acme"
    assert record.ruleset_version == "starter-sap-2026.10"


def test_open_ended_request_is_high_risk(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    result = agent.call(token, "iag.submit_request", {"roles": ["Z_VENDOR_DISPLAY"]})
    assert result.tier is ApprovalTier.HIGH_RISK_WRITE


def test_mitigated_sod_hit_needs_role_and_control_owner(estate: DemoEstate) -> None:
    estate.runtime.inventory.add_mitigations(
        [Mitigation("P2P-01", PRIYA, "CTRL-AP-07", estate.clock.now().date())]
    )
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    args = {"roles": ["Z_VENDOR_MAINT"], "end_date": "2026-11-15"}
    parked = agent.call(token, "iag.submit_request", args)
    assert parked.verdict is Verdict.REQUIRE_APPROVAL
    assert parked.tier is ApprovalTier.HIGH_RISK_WRITE
    one = _approve(estate, parked.approval_task_id, ("user:mark@acme", ApproverRole.ROLE_OWNER))
    assert (
        agent.call(token, "iag.submit_request", args, approvals=one).verdict
        is Verdict.REQUIRE_APPROVAL
    )
    both = [
        *one,
        *_approve(estate, parked.approval_task_id, ("user:cora@acme", ApproverRole.CONTROL_OWNER)),
    ]
    assert agent.call(token, "iag.submit_request", args, approvals=both).verdict is Verdict.ALLOW


def test_unmitigated_high_risk_request_is_denied_outright(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    result = agent.call(
        token, "iag.submit_request", {"roles": ["Z_VENDOR_MAINT"], "end_date": "2026-11-15"}
    )
    assert result.verdict is Verdict.DENY
    assert result.approval_task_id is None


def test_grant_always_needs_approval_and_records_decision_on_assignment(estate: DemoEstate) -> None:
    agent = estate.agent("provisioner")
    inventory = estate.runtime.inventory
    ines = inventory.principal("user:ines@acme")
    inventory.add_principals([replace(ines, entitlements=frozenset({"provision_access"}))])
    token = agent.exchange(estate.user_token(ines.id), "iag", plan_id="p")
    args = {"target": PRIYA, "roles": ["Z_PO_BUYER"], "end_date": "2026-11-10"}
    parked = agent.call(token, "iag.grant_assignment", args)
    assert parked.verdict is Verdict.REQUIRE_APPROVAL
    assert parked.tier is ApprovalTier.HIGH_RISK_WRITE
    approvals = _approve(
        estate,
        parked.approval_task_id,
        ("user:mark@acme", ApproverRole.ROLE_OWNER),
        ("user:cora@acme", ApproverRole.CONTROL_OWNER),
    )
    done = agent.call(token, "iag.grant_assignment", args, approvals=approvals)
    assert done.verdict is Verdict.ALLOW
    [granted] = [
        a
        for a in estate.runtime.inventory.assignments_for(PRIYA, estate.clock.now().date())
        if a.role_id == "Z_PO_BUYER"
    ]
    assert granted.granted_by_decision_id == done.evidence_id


def test_bulk_revoke_needs_reviewer_and_security_admin(estate: DemoEstate) -> None:
    mark = estate.runtime.inventory.principal("user:mark@acme")
    agent = estate.agent("cert-executor")
    token = agent.exchange(estate.user_token(mark.id), "iag", plan_id="p")
    lines = [{"principal": f"user:{i}@acme", "role": "Z_AP_CLERK"} for i in range(26)]
    result = agent.call(token, "review.revoke", {"lines": lines})
    assert result.tier is ApprovalTier.BULK_REVOKE
    small = agent.call(token, "review.revoke", {"lines": lines[:25]})
    assert small.tier is ApprovalTier.LOW_RISK_WRITE


# --- identity and contract checks -----------------------------------------------------------


def test_draft_only_agent_cannot_write_even_if_tool_listed(estate: DemoEstate) -> None:
    agent = estate.agent("certification")
    token = agent.exchange(estate.user_token("user:mark@acme"), "iag", plan_id="p")
    assert (
        agent.call(
            token, "review.draft_decision", {"item": "1", "recommendation": "revoke"}
        ).verdict
        is Verdict.ALLOW
    )
    assert agent.call(token, "review.revoke", {"lines": []}).verdict is Verdict.DENY  # not in scope


def test_delegator_without_entitlement_is_denied(estate: DemoEstate) -> None:
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token("user:sam@acme"), "s4", plan_id="p")
    result = agent.call(token, "s4.vendor_create", {"vendor_id": "V-9"})
    assert result.verdict is Verdict.DENY
    assert "default deny" in result.reason


def test_wrong_audience_token_is_rejected(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    # forge the call to an s4 tool with an iag-audience token
    result = estate.agent("ap-automation").call(token, "s4.vendor_get", {"vendor_id": "V-1"})
    assert result.verdict is Verdict.DENY
    assert "invalid token" in result.reason


def test_unknown_tool_is_denied_and_recorded(estate: DemoEstate) -> None:
    result = estate.runtime.gateway.handle(
        ToolCall("sap.delete_everything", {}, "t", None, "https://x")
    )
    assert result.verdict is Verdict.DENY
    assert estate.runtime.evidence.get(result.evidence_id or "").details["reason"] == "unknown tool"


def test_quarantine_revokes_tokens_and_blocks_writes(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    estate.runtime.quarantine(agent.principal_id, "deny-rate spike")
    assert "revoked" in agent.call(token, "catalog.search_roles", {}).reason
    estate.clock.advance(timedelta(seconds=1))  # type: ignore[attr-defined]
    fresh = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    assert "iag.submit_request" not in fresh.scope
    assert agent.call(fresh, "catalog.search_roles", {}).verdict is Verdict.ALLOW


def test_triggered_anomaly_monitor_can_quarantine_within_envelope(estate: DemoEstate) -> None:
    monitor = estate.agent("anomaly-monitor")
    token = monitor.exchange(estate.trigger_token("etd-alerts", "8812"), "gateway", plan_id="p-etd")
    result = monitor.call(
        token, "gateway.quarantine", {"agent": "agent:access-request@1.3.0", "reason": "burst"}
    )
    assert result.verdict is Verdict.ALLOW, result.reason
    assert estate.runtime.registry.get("agent:access-request@1.3.0").quarantined


def test_suspended_delegator_is_denied(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    inventory = estate.runtime.inventory
    inventory.add_principals(
        [replace(inventory.principal(PRIYA), status=PrincipalStatus.SUSPENDED)]
    )
    assert (
        agent.call(token, "catalog.search_roles", {}).reason == "delegating principal is not active"
    )


# --- engine references ---------------------------------------------------------------------


def test_verdict_claims_without_engine_reference_are_rejected(estate: DemoEstate) -> None:
    agent = estate.agent("certification")
    token = agent.exchange(estate.user_token("user:mark@acme"), "iag", plan_id="p")
    bad = agent.call(token, "review.draft_decision", {"item": "1", "compliant": True})
    assert bad.verdict is Verdict.DENY
    assert "without an engine result_ref" in bad.reason
    fake = agent.call(
        token,
        "review.draft_decision",
        {"item": "1", "compliant": True, "sod_result_ref": "ev_fake"},
    )
    assert "does not exist" in fake.reason
    not_sod = agent.call(
        token,
        "review.draft_decision",
        {"item": "1", "compliant": True, "sod_result_ref": bad.evidence_id},
    )
    assert "not an SoD verdict" in not_sod.reason


def test_verdict_claims_citing_a_real_sod_verdict_are_accepted(estate: DemoEstate) -> None:
    ap = estate.agent("access-request")
    token = ap.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    sod_ref = ap.call(
        token, "iag.submit_request", {"roles": ["Z_VENDOR_MAINT"], "end_date": "2026-11-15"}
    ).sod_result_ref
    cert = estate.agent("certification")
    ctoken = cert.exchange(estate.user_token("user:mark@acme"), "iag", plan_id="p")
    ok = cert.call(
        ctoken,
        "review.draft_decision",
        {"item": "1", "compliant": False, "sod_result_ref": sod_ref},
    )
    assert ok.verdict is Verdict.ALLOW


# --- fail closed --------------------------------------------------------------------------


class _BrokenEvidence:
    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.down = False

    def append(self, *a: Any, **kw: Any) -> Any:
        if self.down:
            raise EvidenceUnavailableError("disk full")
        return self.inner.append(*a, **kw)

    def get(self, record_id: str) -> Any:
        return self.inner.get(record_id)


def test_evidence_outage_denies_writes_and_serves_reads_from_cache(estate: DemoEstate) -> None:
    broken = _BrokenEvidence(estate.runtime.evidence)
    estate.runtime.gateway.evidence = broken
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    fresh = agent.call(token, "catalog.search_roles", {"query": "vendor"})
    assert fresh.verdict is Verdict.ALLOW
    assert not fresh.stale

    broken.down = True
    cached = agent.call(token, "catalog.search_roles", {"query": "vendor"})
    assert cached.verdict is Verdict.ALLOW
    assert cached.stale
    assert cached.result == fresh.result
    uncached = agent.call(token, "catalog.search_roles", {"query": "never-seen"})
    assert uncached.verdict is Verdict.DENY
    write = agent.call(
        token, "iag.submit_request", {"roles": ["Z_VENDOR_DISPLAY"], "end_date": "2026-11-15"}
    )
    assert write.verdict is Verdict.DENY
    assert write.reason.startswith("fail closed")


def test_policy_engine_failure_fails_closed(
    estate: DemoEstate, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise PolicyEngineError("cedar unavailable")

    monkeypatch.setattr(estate.runtime.policy, "evaluate", boom)
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    result = agent.call(token, "s4.vendor_create", {"vendor_id": "V-1"})
    assert result.verdict is Verdict.DENY
    assert "cedar unavailable" in result.reason


def test_sod_engine_failure_fails_closed(
    estate: DemoEstate, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("store offline")

    monkeypatch.setattr(estate.runtime.session, "check", boom)
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    result = agent.call(token, "s4.vendor_create", {"vendor_id": "V-1"})
    assert result.verdict is Verdict.DENY
    assert "SoD engine unavailable" in result.reason


def test_tool_failure_after_allow_keeps_decision_and_skips_session_record(
    estate: DemoEstate,
) -> None:
    def failing(args: Mapping[str, Any], ctx: Any) -> dict[str, Any]:
        raise RuntimeError("S/4 timeout")

    estate.runtime.backend.register("s4.vendor_get", failing)  # type: ignore[attr-defined]
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    result = agent.call(token, "s4.vendor_get", {"vendor_id": "V-1"})
    assert result.verdict is Verdict.ALLOW
    assert result.result == {"error": "S/4 timeout"}


def test_every_decision_is_evidenced_and_chain_verifies(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    for _ in range(3):
        agent.call(token, "catalog.search_roles", {})
    agent.call(token, "iag.submit_request", {"roles": ["Z_VENDOR_MAINT"], "end_date": "2026-11-15"})
    kinds = [r.kind for r in estate.runtime.evidence.records("acme")]
    assert kinds.count("gateway.decision") == 4
    assert kinds.count("sod.verdict") == 1
    assert estate.runtime.evidence.verify("acme", "2026-10-27").ok


@pytest.mark.perf
def test_gateway_decision_latency(estate: DemoEstate) -> None:
    """Spec NFR: p95 < 50 ms, p99 < 150 ms excluding tool time (in-process benchmark)."""
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    samples = []
    for i in range(300):
        started = time.perf_counter()
        agent.call(token, "s4.vendor_create" if i % 2 else "s4.vendor_get", {"vendor_id": f"V-{i}"})
        samples.append(time.perf_counter() - started)
    cuts = statistics.quantiles(samples, n=100)
    p95, p99 = cuts[94], cuts[98]
    assert p95 < 0.050, f"p95 {p95 * 1000:.1f} ms"
    assert p99 < 0.150, f"p99 {p99 * 1000:.1f} ms"
