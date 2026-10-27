# SPDX-License-Identifier: Apache-2.0
"""Core governed entities: principals, roles, entitlements, assignments and mitigations."""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum


class PrincipalKind(StrEnum):
    HUMAN = "human"
    NHI = "nhi"
    AGENT = "agent"
    TRIGGER = "trigger"


class PrincipalStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


@dataclass(frozen=True, slots=True)
class Principal:
    """Any identity whose access is governed.

    ``entitlements`` are governance-level permissions (for example
    ``request_access_self_or_reports``) that Cedar policies check on the delegating principal;
    they are distinct from the technical authorizations granted by roles.
    """

    id: str
    kind: PrincipalKind
    owner_id: str | None = None
    status: PrincipalStatus = PrincipalStatus.ACTIVE
    source_system: str = "local"
    display_name: str = ""
    entitlements: frozenset[str] = frozenset()
    manager_id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("principal id must not be empty")
        if self.kind in (PrincipalKind.NHI, PrincipalKind.TRIGGER) and not self.owner_id:
            raise ValueError(f"{self.kind} principal {self.id!r} requires a human owner")

    @property
    def active(self) -> bool:
        return self.status is PrincipalStatus.ACTIVE


@dataclass(frozen=True, slots=True)
class Entitlement:
    """One technical authorization value, e.g. ``(S4, S_TCODE, TCD, FB60)``.

    ``value`` may be ``*`` (any value) or end in ``*`` (prefix match), as in SAP authorizations.
    """

    system: str
    auth_object: str
    field: str
    value: str

    def satisfies(self, required: str) -> bool:
        if self.value in ("*", required):
            return True
        return self.value.endswith("*") and required.startswith(self.value[:-1])


@dataclass(frozen=True, slots=True)
class Role:
    role_id: str
    system: str
    entitlements: tuple[Entitlement, ...] = ()
    description: str = ""
    owner_id: str | None = None
    critical: bool = False


@dataclass(frozen=True, slots=True)
class Assignment:
    principal_id: str
    role_id: str
    system: str
    valid_from: date | None = None
    valid_to: date | None = None
    granted_by_decision_id: str | None = None

    def active_on(self, day: date) -> bool:
        if self.valid_from is not None and day < self.valid_from:
            return False
        return self.valid_to is None or day <= self.valid_to


@dataclass(frozen=True, slots=True)
class Mitigation:
    """A compensating control that accepts a risk for one principal until ``valid_to``."""

    risk_id: str
    principal_id: str
    control_id: str
    valid_to: date

    def active_on(self, day: date) -> bool:
        return day <= self.valid_to


@dataclass
class Inventory:
    """Thread-safe in-memory store of the governed estate, filled by read connectors."""

    _principals: dict[str, Principal] = field(default_factory=dict)
    _roles: dict[str, Role] = field(default_factory=dict)
    _assignments: dict[str, list[Assignment]] = field(default_factory=lambda: defaultdict(list))
    _mitigations: dict[str, list[Mitigation]] = field(default_factory=lambda: defaultdict(list))
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def add_principals(self, principals: Iterable[Principal]) -> None:
        with self._lock:
            for principal in principals:
                self._principals[principal.id] = principal

    def add_roles(self, roles: Iterable[Role]) -> None:
        with self._lock:
            for role in roles:
                self._roles[role.role_id] = role

    def add_assignments(self, assignments: Iterable[Assignment]) -> None:
        with self._lock:
            for assignment in assignments:
                self._assignments[assignment.principal_id].append(assignment)

    def add_mitigations(self, mitigations: Iterable[Mitigation]) -> None:
        with self._lock:
            for mitigation in mitigations:
                self._mitigations[mitigation.principal_id].append(mitigation)

    def principal(self, principal_id: str) -> Principal:
        with self._lock:
            try:
                return self._principals[principal_id]
            except KeyError:
                raise UnknownEntityError(f"unknown principal {principal_id!r}") from None

    def find_principal(self, principal_id: str) -> Principal | None:
        with self._lock:
            return self._principals.get(principal_id)

    def role(self, role_id: str) -> Role:
        with self._lock:
            try:
                return self._roles[role_id]
            except KeyError:
                raise UnknownEntityError(f"unknown role {role_id!r}") from None

    def roles(self) -> list[Role]:
        with self._lock:
            return list(self._roles.values())

    def principals(self) -> list[Principal]:
        with self._lock:
            return list(self._principals.values())

    def assignments_for(self, principal_id: str, on: date) -> list[Assignment]:
        with self._lock:
            return [a for a in self._assignments.get(principal_id, ()) if a.active_on(on)]

    def mitigations_for(self, principal_id: str, on: date) -> list[Mitigation]:
        with self._lock:
            return [m for m in self._mitigations.get(principal_id, ()) if m.active_on(on)]


class UnknownEntityError(LookupError):
    """A principal, role or other referenced entity does not exist."""
