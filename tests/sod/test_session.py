# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import statistics
import time
from datetime import timedelta

import pytest

from agent_governance.core import FixedClock
from agent_governance.model import Inventory, Mitigation
from agent_governance.sod.ruleset import Ruleset
from agent_governance.sod.session import (
    SessionChecker,
    SessionDecision,
    SessionStep,
    SqliteSessionStore,
)
from tests.conftest import TODAY

AGENT = "agent:access-request@1.3.0"
PRIYA = "user:priya@acme"


def step(
    action: str, plan: str = "plan-1", session: str = "s-1", delegator: str = PRIYA, **keys: str
) -> SessionStep:
    return SessionStep(
        system="S4",
        action=action,
        session_id=session,
        plan_id=plan,
        delegator=delegator,
        agent=AGENT,
        object_keys=keys,
    )


@pytest.fixture
def checker(ruleset: Ruleset, inventory: Inventory, clock: FixedClock) -> SessionChecker:
    return SessionChecker(ruleset, SqliteSessionStore(), inventory, clock)


def test_first_step_is_allowed(checker: SessionChecker) -> None:
    result = checker.check(step("XK01", vendor_id="V100"))
    assert result.decision is SessionDecision.ALLOW
    assert result.violations == ()


def test_create_vendor_then_invoice_same_vendor_is_denied(checker: SessionChecker) -> None:
    executed = checker.record(step("XK01", vendor_id="V100"))
    result = checker.check(step("FB60", vendor_id="V100", company_code="1000"))
    assert result.decision is SessionDecision.DENY
    [violation] = result.violations
    assert violation.risk_id == "P2P-01"
    assert violation.conflicting_step is not None
    assert violation.conflicting_step.step_id == executed.step_id
    assert violation.proof.rule in {"proposed_completes_pair_a", "proposed_completes_pair_b"}


def test_order_does_not_matter(checker: SessionChecker) -> None:
    checker.record(step("FB60", vendor_id="V100"))
    assert checker.check(step("XK01", vendor_id="V100")).decision is SessionDecision.DENY


def test_unrelated_objects_are_allowed(checker: SessionChecker) -> None:
    checker.record(step("XK01", vendor_id="V100"))
    assert checker.check(step("FB60", vendor_id="V200")).decision is SessionDecision.ALLOW


def test_missing_join_key_is_treated_as_related(checker: SessionChecker) -> None:
    checker.record(step("XK01", vendor_id="V100"))
    assert checker.check(step("FB60")).decision is SessionDecision.DENY


def test_splitting_across_sessions_and_plans_does_not_evade(checker: SessionChecker) -> None:
    checker.record(step("XK01", plan="plan-1", session="s-1", vendor_id="V100"))
    result = checker.check(step("FB60", plan="plan-2", session="s-2", vendor_id="V100"))
    assert result.decision is SessionDecision.DENY


def test_rolling_window_expires_for_other_plans(checker: SessionChecker, clock: FixedClock) -> None:
    checker.record(step("XK01", plan="plan-1", vendor_id="V100"))
    clock.advance(timedelta(hours=24, minutes=1))
    assert (
        checker.check(step("FB60", plan="plan-2", vendor_id="V100")).decision
        is SessionDecision.ALLOW
    )
    # ...but the plan scope has no time limit
    assert (
        checker.check(step("FB60", plan="plan-1", vendor_id="V100")).decision
        is SessionDecision.DENY
    )


def test_other_delegators_do_not_interfere(checker: SessionChecker) -> None:
    checker.record(step("XK01", plan="plan-a", delegator="user:sam@acme", vendor_id="V100"))
    assert (
        checker.check(step("FB60", plan="plan-b", vendor_id="V100")).decision
        is SessionDecision.ALLOW
    )


def test_medium_risk_requires_approval(checker: SessionChecker) -> None:
    checker.record(step("ME21N", purchase_order="4500000001"))
    result = checker.check(step("ME29N", purchase_order="4500000001"))
    assert result.decision is SessionDecision.REQUIRE_APPROVAL
    assert result.violations[0].risk_id == "P2P-04"


def test_mitigated_high_risk_requires_approval_instead_of_deny(
    checker: SessionChecker, inventory: Inventory
) -> None:
    inventory.add_mitigations([Mitigation("P2P-01", PRIYA, "CTRL-AP-07", TODAY)])
    checker.record(step("XK01", vendor_id="V100"))
    result = checker.check(step("FB60", vendor_id="V100"))
    assert result.decision is SessionDecision.REQUIRE_APPROVAL
    assert result.violations[0].mitigated_by == ("CTRL-AP-07",)


def test_critical_function_requires_approval_on_first_use(checker: SessionChecker) -> None:
    result = checker.check(step("SE38_DEBUG_CHANGE"))
    assert result.decision is SessionDecision.REQUIRE_APPROVAL
    assert result.violations[0].critical


def test_worst_violation_wins(checker: SessionChecker) -> None:
    checker.record(step("XK01", vendor_id="V100"))  # P2P-01 (high) with FB60...
    checker.record(step("F110", vendor_id="V100", company_code="1000"))  # P2P-03 (high) with FB60
    result = checker.check(step("FB60", vendor_id="V100", company_code="1000"))
    assert result.decision is SessionDecision.DENY
    assert {v.risk_id for v in result.violations} == {"P2P-01", "P2P-03"}


def test_unrecorded_steps_never_count(checker: SessionChecker) -> None:
    checker.check(step("XK01", vendor_id="V100"))  # checked, never executed
    assert checker.check(step("FB60", vendor_id="V100")).decision is SessionDecision.ALLOW


def test_record_requires_or_assigns_timestamp(checker: SessionChecker, clock: FixedClock) -> None:
    executed = checker.record(step("XK01"))
    assert executed.ts == clock.now()
    with pytest.raises(ValueError, match="timestamp"):
        SqliteSessionStore().append(step("XK01"))


@pytest.mark.perf
def test_session_check_p95_under_150ms_with_10k_step_window(
    ruleset: Ruleset, inventory: Inventory, clock: FixedClock
) -> None:
    store = SqliteSessionStore()
    checker = SessionChecker(ruleset, store, inventory, clock)
    actions = ["XK01", "FB60", "F110", "ME21N", "MIGO", "FB50", "XD01", "F-28"]
    for i in range(10_000):
        checker.record(
            step(
                actions[i % len(actions)], plan=f"p{i % 50}", vendor_id=f"V{i}", company_code="1000"
            )
        )
    samples = []
    for i in range(200):
        started = time.perf_counter()
        checker.check(step("FB60", plan=f"p{i % 50}", vendor_id=f"V{i}", company_code="1000"))
        samples.append(time.perf_counter() - started)
    p95 = statistics.quantiles(samples, n=20)[-1]
    assert p95 < 0.150, f"session check p95 {p95 * 1000:.1f} ms"
