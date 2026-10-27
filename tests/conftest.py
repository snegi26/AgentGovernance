# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from agent_governance.core import FixedClock
from agent_governance.model import (
    Assignment,
    Entitlement,
    Inventory,
    Principal,
    PrincipalKind,
    Role,
)
from agent_governance.sod.ruleset import Ruleset

TODAY = date(2026, 10, 27)
NOW = datetime(2026, 10, 27, 14, 0, tzinfo=UTC)


def sap_role(role_id: str, *rows: tuple[str, str, str]) -> Role:
    """A role from AGR_1251-shaped rows: (OBJECT, FIELD, LOW)."""
    return Role(role_id, "S4", tuple(Entitlement("S4", o, f, v) for o, f, v in rows))


ROLES = [
    sap_role("Z_AP_CLERK", ("S_TCODE", "TCD", "FB60"), ("F_BKPF_BUK", "ACTVT", "01")),
    sap_role("Z_VENDOR_MAINT", ("S_TCODE", "TCD", "XK01"), ("F_LFA1_APP", "ACTVT", "01")),
    sap_role("Z_VENDOR_DISPLAY", ("S_TCODE", "TCD", "XK03"), ("F_LFA1_APP", "ACTVT", "03")),
    # Holds the transaction code but not the application object: cannot post invoices.
    sap_role("Z_FB60_TCODE_ONLY", ("S_TCODE", "TCD", "FB60")),
    # Prefix wildcard: every F* transaction with full document posting authority.
    sap_role("Z_FIN_POWER", ("S_TCODE", "TCD", "F*"), ("F_BKPF_BUK", "ACTVT", "*")),
    sap_role("Z_PAYMENTS", ("S_TCODE", "TCD", "F110"), ("F_REGU_BUK", "FBTCH", "11")),
    sap_role(
        "Z_BASIS_DEBUG",
        ("S_TCODE", "TCD", "SE38"),
        ("S_DEVELOP", "OBJTYPE", "DEBUG"),
        ("S_DEVELOP", "ACTVT", "*"),
    ),
]


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(NOW)


@pytest.fixture
def ruleset() -> Ruleset:
    return Ruleset.starter()


@pytest.fixture
def inventory() -> Inventory:
    inv = Inventory()
    inv.add_roles(ROLES)
    inv.add_principals(
        [
            Principal("user:priya@acme", PrincipalKind.HUMAN, manager_id="user:mark@acme"),
            Principal("user:mark@acme", PrincipalKind.HUMAN),
            Principal("user:sam@acme", PrincipalKind.HUMAN),
            Principal("svc:sap-batch-07", PrincipalKind.NHI, owner_id="user:mark@acme"),
        ]
    )
    inv.add_assignments(
        [
            Assignment("user:priya@acme", "Z_AP_CLERK", "S4"),
            Assignment("user:sam@acme", "Z_AP_CLERK", "S4"),
            Assignment("user:sam@acme", "Z_VENDOR_MAINT", "S4"),
            Assignment("user:mark@acme", "Z_VENDOR_DISPLAY", "S4"),
            Assignment("user:mark@acme", "Z_FB60_TCODE_ONLY", "S4"),
        ]
    )
    return inv
