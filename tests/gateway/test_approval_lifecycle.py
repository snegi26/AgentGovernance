# SPDX-License-Identifier: Apache-2.0
"""Approval lifecycle through the gateway: single use, final rejection, request targets."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agent_governance.approval.service import ApprovalError
from agent_governance.approval.tiers import ApproverRole
from agent_governance.demo.estate import DemoEstate
from agent_governance.gateway.gateway import Verdict
from agent_governance.model import Mitigation

PRIYA = "user:priya@acme"


def test_approvals_are_single_use(estate: DemoEstate) -> None:
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    args = {"vendor_id": "V-1"}
    parked = agent.call(token, "s4.vendor_create", args)
    approval = estate.runtime.approvals.approve(
        parked.approval_task_id or "", "user:mark@acme", ApproverRole.LINE_MANAGER
    )
    assert (
        agent.call(token, "s4.vendor_create", args, approvals=[approval]).verdict is Verdict.ALLOW
    )

    replay = agent.call(token, "s4.vendor_create", args, approvals=[approval])
    assert replay.verdict is Verdict.REQUIRE_APPROVAL
    problems = estate.runtime.evidence.get(replay.evidence_id or "").details["approval_problems"]
    assert any("already used" in p for p in problems)
    assert replay.approval_task_id != parked.approval_task_id  # a fresh task for a fresh execution
    assert [c[0] for c in estate.runtime.backend.calls] == ["s4.vendor_create"]  # type: ignore[attr-defined]


def test_rejection_is_final_for_that_payload(estate: DemoEstate) -> None:
    estate.runtime.inventory.add_mitigations(
        [Mitigation("P2P-01", PRIYA, "CTRL-AP-07", estate.clock.now().date())]
    )
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    args = {"roles": ["Z_VENDOR_MAINT"], "end_date": "2026-11-15"}
    parked = agent.call(token, "iag.submit_request", args)
    approvals = estate.runtime.approvals
    role_owner = approvals.approve(
        parked.approval_task_id or "", "user:mark@acme", ApproverRole.ROLE_OWNER
    )
    approvals.reject(parked.approval_task_id or "", "user:cora@acme", "no business need")

    again = agent.call(token, "iag.submit_request", args, approvals=[role_owner])
    assert again.verdict is Verdict.DENY
    assert again.reason == "an approver rejected this exact payload"
    assert again.approval_task_id == parked.approval_task_id  # not replaced by a fresh task


def test_only_task_approvers_can_reject(estate: DemoEstate) -> None:
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    task_id = agent.call(token, "s4.vendor_create", {"vendor_id": "V-2"}).approval_task_id or ""
    approvals = estate.runtime.approvals
    for intruder in (PRIYA, "user:sam@acme"):
        with pytest.raises(ApprovalError, match="may not decide"):
            approvals.reject(task_id, intruder, "sabotage")
    assert approvals.task(task_id).status.value == "pending"


def test_requests_only_for_self_or_direct_reports(estate: DemoEstate) -> None:
    agent = estate.agent("access-request")
    priya = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    other = agent.call(
        priya,
        "iag.submit_request",
        {"target": "user:sam@acme", "roles": ["Z_VENDOR_DISPLAY"], "end_date": "2026-11-15"},
    )
    assert other.verdict is Verdict.DENY
    assert "themselves or direct reports" in other.reason

    inventory = estate.runtime.inventory
    mark = inventory.principal("user:mark@acme")
    inventory.add_principals(
        [replace(mark, entitlements=mark.entitlements | {"request_access_self_or_reports"})]
    )
    manager = agent.exchange(estate.user_token(mark.id), "iag", plan_id="p")
    report = agent.call(
        manager,
        "iag.submit_request",
        {"target": PRIYA, "roles": ["Z_VENDOR_DISPLAY"], "end_date": "2026-11-15"},
    )
    assert report.verdict is Verdict.REQUIRE_APPROVAL


def test_float_arguments_are_decided_and_recorded(estate: DemoEstate) -> None:
    agent = estate.agent("ap-automation")
    token = agent.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    result = agent.call(
        token, "s4.invoice_post", {"vendor_id": "V-7", "company_code": "1000", "amount": 48250.5}
    )
    assert result.verdict is Verdict.REQUIRE_APPROVAL
    assert result.evidence_id is not None


def test_unexpected_errors_fail_closed_with_a_record(
    estate: DemoEstate, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: object, **__: object) -> None:
        raise ZeroDivisionError

    monkeypatch.setattr(estate.runtime.gateway, "_decide", boom)
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    result = agent.call(token, "catalog.search_roles", {})
    assert result.verdict is Verdict.DENY
    assert result.reason == "internal error: ZeroDivisionError"
    assert result.evidence_id is not None


def test_trigger_owner_is_the_line_manager_for_triggered_work(estate: DemoEstate) -> None:
    directory = estate.runtime.directory
    assert directory.holds(
        "user:raj@acme", ApproverRole.LINE_MANAGER, delegator="trigger:etd-alerts"
    )
    assert not directory.holds(
        "user:mark@acme", ApproverRole.LINE_MANAGER, delegator="trigger:etd-alerts"
    )
    assert not directory.holds(
        "user:raj@acme", ApproverRole.LINE_MANAGER, delegator="trigger:unknown"
    )
