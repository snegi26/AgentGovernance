# SPDX-License-Identifier: Apache-2.0
"""Read-only connector interface. Provisioning stays with the customer's provisioning engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from agent_governance.model import Assignment, Inventory, Principal, Role


@dataclass(frozen=True, slots=True)
class Snapshot:
    system: str
    principals: tuple[Principal, ...] = ()
    roles: tuple[Role, ...] = ()
    assignments: tuple[Assignment, ...] = ()
    warnings: tuple[str, ...] = field(default=())


class Connector(Protocol):
    system: str

    def snapshot(self) -> Snapshot:
        """Read principals, roles (with technical entitlements) and assignments."""
        ...


def load_into(inventory: Inventory, *connectors: Connector) -> list[str]:
    """Load every connector's snapshot; returns accumulated warnings."""
    warnings: list[str] = []
    for connector in connectors:
        snap = connector.snapshot()
        inventory.add_principals(snap.principals)
        inventory.add_roles(snap.roles)
        inventory.add_assignments(snap.assignments)
        warnings += [f"{snap.system}: {w}" for w in snap.warnings]
    return warnings
