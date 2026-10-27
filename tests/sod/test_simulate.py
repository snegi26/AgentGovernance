# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from agent_governance.core import FixedClock
from agent_governance.model import Inventory
from agent_governance.sod.engine import SodEngine
from agent_governance.sod.ruleset import Ruleset


def test_adding_a_role_reports_added_violation(
    ruleset: Ruleset, inventory: Inventory, clock: FixedClock
) -> None:
    engine = SodEngine(ruleset, inventory, clock)
    result = engine.simulate("user:priya@acme", add_roles=["Z_VENDOR_MAINT"])
    assert [v.risk_id for v in result.added] == ["P2P-01"]
    assert result.removed == ()
    # simulation never mutates the inventory
    assert engine.static("user:priya@acme").violations == ()


def test_removing_a_role_reports_removed_violation(
    ruleset: Ruleset, inventory: Inventory, clock: FixedClock
) -> None:
    engine = SodEngine(ruleset, inventory, clock)
    result = engine.simulate("user:sam@acme", remove_roles=["Z_AP_CLERK"])
    assert [v.risk_id for v in result.removed] == ["P2P-01"]
    assert result.added == ()
    assert result.to_dict()["unchanged"] == []


def test_swap_reports_both_directions(
    ruleset: Ruleset, inventory: Inventory, clock: FixedClock
) -> None:
    engine = SodEngine(ruleset, inventory, clock)
    result = engine.simulate("user:sam@acme", add_roles=["Z_PAYMENTS"], remove_roles=["Z_AP_CLERK"])
    assert {v.risk_id for v in result.added} == {"P2P-02"}
    assert {v.risk_id for v in result.removed} == {"P2P-01"}
