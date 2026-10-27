# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import timedelta

import jwt
import pytest

from agent_governance.approval.service import (
    ApprovalError,
    ApprovalService,
    ApproverDirectory,
    TaskStatus,
)
from agent_governance.approval.tiers import ApprovalTier, ApproverRole, strictest
from agent_governance.core import FixedClock
from agent_governance.crypto import generate_ed25519_key
from agent_governance.evidence.store import EvidenceStore
from agent_governance.model import Inventory

PRIYA = "user:priya@acme"


@pytest.fixture
def service(inventory: Inventory, clock: FixedClock) -> ApprovalService:
    directory = ApproverDirectory(
        inventory,
        {
            ApproverRole.ROLE_OWNER: ["user:mark@acme", "user:sam@acme"],
            ApproverRole.CONTROL_OWNER: ["user:sam@acme", PRIYA],
        },
    )
    return ApprovalService(
        tenant="acme",
        signing_key=generate_ed25519_key(),
        directory=directory,
        evidence=EvidenceStore(clock=clock),
        clock=clock,
    )


def _task(
    service: ApprovalService, tier: ApprovalTier = ApprovalTier.HIGH_RISK_WRITE, h: str = "sha256:h"
) -> str:
    return service.open_task(
        call_hash=h, tier=tier, tool_id="iag.submit_request", delegator=PRIYA, summary={}
    ).task_id


def test_full_approval_verifies(service: ApprovalService) -> None:
    task = _task(service)
    a = service.approve(task, "user:mark@acme", ApproverRole.ROLE_OWNER)
    b = service.approve(task, "user:sam@acme", ApproverRole.CONTROL_OWNER)
    assert service.task(task).status is TaskStatus.APPROVED
    check = service.verify(
        [a, b], call_hash="sha256:h", tier=ApprovalTier.HIGH_RISK_WRITE, delegator=PRIYA
    )
    assert check.valid
    assert set(check.approvers) == {"user:mark@acme", "user:sam@acme"}


def test_open_task_is_idempotent_per_payload(service: ApprovalService) -> None:
    assert _task(service) == _task(service)
    assert _task(service, h="sha256:other") != _task(service)


def test_line_manager_comes_from_inventory(service: ApprovalService) -> None:
    task = _task(service, ApprovalTier.LOW_RISK_WRITE)
    with pytest.raises(ApprovalError, match="does not hold"):
        service.approve(task, "user:sam@acme", ApproverRole.LINE_MANAGER)
    token = service.approve(task, "user:mark@acme", ApproverRole.LINE_MANAGER)
    assert service.verify(
        [token], call_hash="sha256:h", tier=ApprovalTier.LOW_RISK_WRITE, delegator=PRIYA
    ).valid


@pytest.mark.parametrize(
    ("approver", "role", "message"),
    [
        (PRIYA, ApproverRole.CONTROL_OWNER, "own request"),
        ("user:mark@acme", ApproverRole.CONTROL_OWNER, "does not hold"),
        ("user:mark@acme", ApproverRole.SECURITY_ADMIN, "does not take"),
    ],
)
def test_approve_guards(
    service: ApprovalService, approver: str, role: ApproverRole, message: str
) -> None:
    with pytest.raises(ApprovalError, match=message):
        service.approve(_task(service), approver, role)


def test_one_person_cannot_fill_two_roles(service: ApprovalService) -> None:
    task = _task(service)
    service.approve(task, "user:sam@acme", ApproverRole.ROLE_OWNER)
    with pytest.raises(ApprovalError, match="two roles"):
        service.approve(task, "user:sam@acme", ApproverRole.CONTROL_OWNER)
    with pytest.raises(ApprovalError, match="already approved"):
        service.approve(task, "user:mark@acme", ApproverRole.ROLE_OWNER)


def test_verify_rejects_partial_wrong_hash_expired_and_forged(
    service: ApprovalService, clock: FixedClock
) -> None:
    task = _task(service)
    a = service.approve(task, "user:mark@acme", ApproverRole.ROLE_OWNER)
    partial = service.verify(
        [a], call_hash="sha256:h", tier=ApprovalTier.HIGH_RISK_WRITE, delegator=PRIYA
    )
    assert not partial.valid
    assert "missing approvals: control_owner" in partial.problems
    other = service.verify(
        [a], call_hash="sha256:x", tier=ApprovalTier.HIGH_RISK_WRITE, delegator=PRIYA
    )
    assert any("different payload" in p for p in other.problems)
    forged = jwt.encode(
        {
            "iss": "agent-governance/approvals",
            "call_hash": "sha256:h",
            "approver": "user:sam@acme",
            "role": "control_owner",
            "exp": 9_999_999_999,
        },
        generate_ed25519_key(),
        algorithm="EdDSA",
    )
    assert not service.verify(
        [a, forged], call_hash="sha256:h", tier=ApprovalTier.HIGH_RISK_WRITE, delegator=PRIYA
    ).valid
    clock.advance(timedelta(hours=25))
    expired = service.verify(
        [a], call_hash="sha256:h", tier=ApprovalTier.HIGH_RISK_WRITE, delegator=PRIYA
    )
    assert any("expired" in p for p in expired.problems)


def test_revoked_approver_role_invalidates_existing_approval(
    service: ApprovalService, inventory: Inventory
) -> None:
    task = _task(service, ApprovalTier.LOW_RISK_WRITE)
    token = service.approve(task, "user:mark@acme", ApproverRole.LINE_MANAGER)
    from dataclasses import replace

    inventory.add_principals([replace(inventory.principal(PRIYA), manager_id="user:sam@acme")])
    assert not service.verify(
        [token], call_hash="sha256:h", tier=ApprovalTier.LOW_RISK_WRITE, delegator=PRIYA
    ).valid


def test_rejected_task_blocks_even_with_approvals(service: ApprovalService) -> None:
    task = _task(service)
    token = service.approve(task, "user:mark@acme", ApproverRole.ROLE_OWNER)
    service.reject(task, "user:sam@acme", "control owner declines")
    check = service.verify(
        [token], call_hash="sha256:h", tier=ApprovalTier.LOW_RISK_WRITE, delegator=PRIYA
    )
    assert not check.valid
    assert "the approval task was rejected" in check.problems
    with pytest.raises(ApprovalError, match="not open"):
        service.reject(task, "user:mark@acme", "again")
    with pytest.raises(ApprovalError, match="not open"):
        service.approve(task, "user:sam@acme", ApproverRole.CONTROL_OWNER)


def test_approvals_are_evidenced(service: ApprovalService) -> None:
    task = _task(service, ApprovalTier.LOW_RISK_WRITE)
    service.approve(task, "user:mark@acme", ApproverRole.LINE_MANAGER)
    [record] = service.evidence.records("acme", kinds=["approval"])  # type: ignore[attr-defined]
    assert record.approver == "user:mark@acme"
    assert record.inputs_hash == "sha256:h"


def test_tier_none_needs_no_task_and_always_verifies(service: ApprovalService) -> None:
    with pytest.raises(ApprovalError):
        _task(service, ApprovalTier.NONE)
    assert service.verify([], call_hash="h", tier=ApprovalTier.NONE, delegator=PRIYA).valid


def test_strictest_tier() -> None:
    assert strictest() is ApprovalTier.NONE
    assert (
        strictest(ApprovalTier.LOW_RISK_WRITE, ApprovalTier.HIGH_RISK_WRITE)
        is ApprovalTier.HIGH_RISK_WRITE
    )
    assert (
        strictest(ApprovalTier.BULK_REVOKE, ApprovalTier.HIGH_RISK_WRITE)
        is ApprovalTier.BULK_REVOKE
    )
