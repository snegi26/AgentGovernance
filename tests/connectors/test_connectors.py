# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from datetime import date
from importlib import resources
from typing import Any

from agent_governance.connectors.base import load_into
from agent_governance.connectors.entra import EntraConnector
from agent_governance.connectors.sap import SapS4Connector
from agent_governance.model import Inventory, PrincipalKind, PrincipalStatus


def _fixture(name: str) -> dict[str, Any]:
    return dict(json.loads(resources.files("agent_governance.fixtures").joinpath(name).read_text()))


def test_sap_maps_tables_to_model() -> None:
    snap = SapS4Connector(_fixture("sap_s4.json")).snapshot()
    roles = {r.role_id: r for r in snap.roles}
    assert roles["Z_AP_CLERK"].description.startswith("Accounts payable")
    assert roles["Z_BASIS_DEBUG"].critical
    batch = next(p for p in snap.principals if p.id == "svc:sap-batch07")
    assert batch.kind is PrincipalKind.NHI
    assert batch.owner_id == "user:mark@acme"
    leo = next(a for a in snap.assignments if a.principal_id == "user:leo@acme")
    assert leo.valid_to == date(2025, 12, 31)
    open_ended = next(a for a in snap.assignments if a.principal_id == "user:priya@acme")
    assert open_ended.valid_to is None  # 99991231
    assert any("RFC_ORPHAN" in w for w in snap.warnings)
    assert any("uses a range" in w for w in snap.warnings)


def test_entra_maps_graph_shapes() -> None:
    snap = EntraConnector(_fixture("entra.json")).snapshot()
    by_id = {p.id: p for p in snap.principals}
    assert by_id["user:priya@acme"].manager_id == "user:mark@acme"
    assert by_id["user:leo@acme"].status is PrincipalStatus.SUSPENDED
    assert "request_access_self_or_reports" in by_id["user:priya@acme"].entitlements
    assert by_id["svc:entra-7f1c0a2e-0000-4000-8000-000000000007"].owner_id == "user:mark@acme"
    roles = {r.role_id for r in snap.roles}
    assert "ENTRA:Privileged Role Administrator" in roles
    assert any("legacy-sync" in w for w in snap.warnings)


def test_entra_privileged_role_admin_is_flagged_by_starter_rules() -> None:
    from agent_governance.sod.engine import SodEngine
    from agent_governance.sod.ruleset import Ruleset

    inventory = Inventory()
    load_into(inventory, EntraConnector(_fixture("entra.json")))
    result = SodEngine(Ruleset.starter(), inventory).static(
        "user:ines@acme", as_of=date(2026, 10, 27)
    )
    assert [v.risk_id for v in result.violations] == ["CRIT-03"]


def test_unknown_references_are_warned_not_crashed() -> None:
    data = _fixture("entra.json")
    data["roleAssignments"].append(
        {"id": "ra-x", "principalId": "nobody", "roleDefinitionId": "rd-ga"}
    )
    assert any("ra-x" in w for w in EntraConnector(data).snapshot().warnings)
