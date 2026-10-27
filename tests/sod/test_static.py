# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import date

import pytest

from agent_governance.core import FixedClock
from agent_governance.model import Assignment, Inventory, Mitigation, UnknownEntityError
from agent_governance.sod.engine import PathStep, SodEngine
from agent_governance.sod.ruleset import Ruleset
from tests.conftest import TODAY


@pytest.fixture
def engine(ruleset: Ruleset, inventory: Inventory, clock: FixedClock) -> SodEngine:
    return SodEngine(ruleset, inventory, clock)


def test_clean_user_has_no_violations(engine: SodEngine) -> None:
    result = engine.static("user:priya@acme")
    assert result.violations == ()
    assert result.ruleset_version == "starter-sap-2026.10"


def test_vendor_plus_invoice_is_p2p01_with_proof_path(engine: SodEngine) -> None:
    result = engine.static("user:sam@acme")
    assert [v.risk_id for v in result.violations] == ["P2P-01"]
    violation = result.violations[0]
    assert set(violation.path) == {
        PathStep(
            "F_VENDOR_MAINT",
            "Z_VENDOR_MAINT",
            "S4",
            "XK01",
            (("S_TCODE", "TCD", "XK01"), ("F_LFA1_APP", "ACTVT", "01")),
        ),
        PathStep(
            "F_AP_INVOICE",
            "Z_AP_CLERK",
            "S4",
            "FB60",
            (("S_TCODE", "TCD", "FB60"), ("F_BKPF_BUK", "ACTVT", "01")),
        ),
    }
    # the proof bottoms out in base facts: the assignments and the rule model
    leaves = {(f.predicate, f.args) for f in violation.proof.leaves()}
    assert ("assigned", ("user:sam@acme", "Z_VENDOR_MAINT")) in leaves
    assert ("risk", ("P2P-01", "high", "F_VENDOR_MAINT", "F_AP_INVOICE")) in leaves


def test_transaction_code_alone_does_not_grant_function(engine: SodEngine) -> None:
    # mark holds S_TCODE=FB60 without F_BKPF_BUK, and vendor *display* only.
    assert engine.static("user:mark@acme").violations == ()


def test_prefix_wildcard_grants_matching_actions(engine: SodEngine, inventory: Inventory) -> None:
    inventory.add_assignments([Assignment("user:priya@acme", "Z_FIN_POWER", "S4")])
    ids = {v.risk_id for v in engine.static("user:priya@acme").violations}
    # F* + ACTVT * reaches FB60/F-53/FB75/F-28 but not FK01 (needs F_LFA1_APP)
    # or F110 (needs F_REGU_BUK).
    assert ids == {"P2P-03", "O2C-02"}


def test_critical_single_function(engine: SodEngine, inventory: Inventory) -> None:
    inventory.add_assignments([Assignment("user:priya@acme", "Z_BASIS_DEBUG", "S4")])
    [violation] = engine.static("user:priya@acme").violations
    assert violation.risk_id == "CRIT-01"
    assert violation.critical
    assert violation.functions == ("F_DEBUG_CHANGE",)


def test_violations_sorted_by_severity(engine: SodEngine, inventory: Inventory) -> None:
    inventory.add_assignments(
        [
            Assignment("user:sam@acme", "Z_PAYMENTS", "S4"),
            Assignment("user:sam@acme", "Z_BASIS_DEBUG", "S4"),
        ]
    )
    levels = [v.level.rank for v in engine.static("user:sam@acme").violations]
    assert levels == sorted(levels, reverse=True)


def test_expired_and_future_assignments_are_ignored(
    engine: SodEngine, inventory: Inventory
) -> None:
    inventory.add_assignments(
        [
            Assignment("user:priya@acme", "Z_VENDOR_MAINT", "S4", valid_to=date(2026, 10, 26)),
            Assignment("user:priya@acme", "Z_VENDOR_MAINT", "S4", valid_from=date(2026, 10, 28)),
        ]
    )
    assert engine.static("user:priya@acme").violations == ()
    assert [
        v.risk_id for v in engine.static("user:priya@acme", as_of=date(2026, 10, 28)).violations
    ] == ["P2P-01"]


def test_active_mitigation_marks_but_does_not_hide(engine: SodEngine, inventory: Inventory) -> None:
    inventory.add_mitigations([Mitigation("P2P-01", "user:sam@acme", "CTRL-AP-07", TODAY)])
    [violation] = engine.static("user:sam@acme").violations
    assert violation.mitigated_by == ("CTRL-AP-07",)
    assert engine.static("user:sam@acme").unmitigated == ()
    later = engine.static("user:sam@acme", as_of=date(2026, 10, 28))
    assert later.violations[0].mitigated_by == ()


def test_unknown_principal_is_an_error_not_clean(engine: SodEngine) -> None:
    with pytest.raises(UnknownEntityError):
        engine.static("user:ghost@acme")


def test_to_dict_is_serialisable(engine: SodEngine) -> None:
    from agent_governance.core import canonical_json

    assert b"P2P-01" in canonical_json(engine.static("user:sam@acme").to_dict())
