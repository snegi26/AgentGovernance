# SPDX-License-Identifier: Apache-2.0
"""Eval status caps what an agent may do, checked per call rather than only at token issue."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agent_governance.crypto import ec_public_jwk, generate_ec_key
from agent_governance.demo.estate import DemoEstate
from agent_governance.evidence.record import EvidenceKind
from agent_governance.gateway.backends import InMemoryBackend
from agent_governance.gateway.client import AgentClient
from agent_governance.gateway.gateway import SHADOW, Verdict
from agent_governance.identity.registry import EvalStatus

PRIYA = "user:priya@acme"
MARK = "user:mark@acme"
LIVE_AP = "agent:ap-automation@1.0.0"
SHADOW_AP = "agent:ap-automation@1.1.0"


def _backend(estate: DemoEstate) -> InMemoryBackend:
    backend = estate.runtime.backend
    assert isinstance(backend, InMemoryBackend)
    return backend


def _shadow_candidate(estate: DemoEstate, agent_id: str, version: str) -> AgentClient:
    """Register a shadow version of a live demo agent with the same contract."""
    live = next(a for a in estate.runtime.registry.agents() if a.agent_id == agent_id)
    key = generate_ec_key()
    contract = estate.runtime.registry.register(
        replace(live, version=version, public_jwk=ec_public_jwk(key), eval_status=EvalStatus.SHADOW)
    )
    return AgentClient(estate.runtime, contract.principal_id, key)


@pytest.mark.parametrize("status", [EvalStatus.PENDING, EvalStatus.FAILED])
def test_unevaluated_agent_cannot_write_with_a_token_issued_before(
    estate: DemoEstate, status: EvalStatus
) -> None:
    ap = estate.agent("ap-automation")
    token = ap.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    assert "s4.vendor_create" in token.scope
    estate.runtime.registry.set_eval_status(LIVE_AP, status, approved_by=MARK)

    result = ap.call(token, "s4.vendor_create", {"vendor_id": "V-1"})

    assert result.verdict is Verdict.DENY
    assert result.approval_task_id is None
    assert "autonomy.writes-need-write-autonomy" in result.reason
    assert ap.call(token, "s4.vendor_get", {"vendor_id": "V-1"}).verdict is Verdict.ALLOW
    assert ap.exchange(estate.user_token(PRIYA), "s4", plan_id="p").scope == ("s4.vendor_get",)


def test_shadow_write_is_evaluated_and_recorded_but_not_executed(estate: DemoEstate) -> None:
    candidate = estate.agent("ap-automation@1.1.0")
    token = candidate.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    pending_before = len(estate.runtime.approvals.pending())

    result = candidate.call(token, "s4.vendor_create", {"vendor_id": "V-1"})

    assert result.verdict is Verdict.REQUIRE_APPROVAL
    assert result.shadow
    assert result.approval_task_id is None
    assert result.result is None
    assert len(estate.runtime.approvals.pending()) == pending_before
    assert all(call[2].agent != SHADOW_AP for call in _backend(estate).calls)
    record = estate.runtime.evidence.get(result.evidence_id or "")
    assert record.kind == EvidenceKind.GATEWAY_DECISION
    assert record.verdict == "require_approval"
    assert SHADOW in record.flags
    assert record.details["shadow"] is True


def test_shadow_writes_do_not_count_as_executed_session_steps(estate: DemoEstate) -> None:
    candidate = estate.agent("ap-automation@1.1.0")
    shadow_token = candidate.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    candidate.call(shadow_token, "s4.vendor_create", {"vendor_id": "V-1"})

    live = estate.agent("ap-automation")
    token = live.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    invoice = {"vendor_id": "V-1", "company_code": "1000", "amount": "10.00"}
    result = live.call(token, "s4.invoice_post", invoice)

    # Had the shadow vendor creation counted, this would be denied by P2P-01.
    assert result.verdict is Verdict.REQUIRE_APPROVAL
    assert "P2P-01" not in result.reason


def test_shadow_draft_that_would_be_allowed_is_not_executed(estate: DemoEstate) -> None:
    candidate = _shadow_candidate(estate, "certification", "1.1.0")
    token = candidate.exchange(estate.user_token(MARK), "iag", plan_id="p")

    result = candidate.call(
        token, "review.draft_decision", {"item": "1", "recommendation": "revoke"}
    )

    assert result.verdict is Verdict.ALLOW
    assert result.shadow
    assert result.result is None
    assert all(call[2].agent != candidate.principal_id for call in _backend(estate).calls)


def test_shadow_reads_are_executed(estate: DemoEstate) -> None:
    candidate = estate.agent("ap-automation@1.1.0")
    token = candidate.exchange(estate.user_token(PRIYA), "s4", plan_id="p")

    result = candidate.call(token, "s4.vendor_get", {"vendor_id": "V-1"})

    assert result.verdict is Verdict.ALLOW
    assert not result.shadow
    assert result.result is not None
    assert SHADOW not in result.flags


def test_promoting_a_shadow_agent_lets_its_writes_through(estate: DemoEstate) -> None:
    candidate = estate.agent("ap-automation@1.1.0")
    token = candidate.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    estate.runtime.registry.set_eval_status(
        SHADOW_AP, EvalStatus.PASSED, approved_by=MARK, eval_run="ev-run-1"
    )

    result = candidate.call(token, "s4.vendor_create", {"vendor_id": "V-1"})

    assert result.verdict is Verdict.REQUIRE_APPROVAL
    assert not result.shadow
    assert result.approval_task_id is not None
