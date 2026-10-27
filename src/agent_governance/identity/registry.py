# SPDX-License-Identifier: Apache-2.0
"""Agent registry and trigger registrations.

Every agent is a registered client with its own key pair, an owner and a contract listing
the tools it may call. Triggers bind an event source to a fixed policy envelope that a named
human owner approved at registration, which gives event-started work a human principal to
answer for it.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Any

from agent_governance.crypto import jwk_thumbprint
from agent_governance.model import Inventory, PrincipalKind


class Autonomy(StrEnum):
    READ = "read"
    DRAFT = "draft"
    WRITE_WITH_APPROVAL = "write_with_approval"
    WRITE = "write"

    @property
    def rank(self) -> int:
        return {"read": 0, "draft": 1}.get(self.value, 2)


class EvalStatus(StrEnum):
    PENDING = "pending"
    SHADOW = "shadow"
    PASSED = "passed"
    FAILED = "failed"


class RegistryError(ValueError):
    pass


class UnknownAgentError(LookupError):
    pass


@dataclass(frozen=True, slots=True)
class AgentContract:
    agent_id: str
    version: str
    owner: str
    model_ref: str
    allowed_tools: frozenset[str]
    max_autonomy: Autonomy
    public_jwk: dict[str, str]
    risk_tier: str = "medium"
    eval_status: EvalStatus = EvalStatus.PENDING
    evals: tuple[str, ...] = ()
    retired_at: datetime | None = None
    quarantined: bool = False
    #: Autonomy to restore after a quarantine; ``None`` when not quarantined.
    pre_quarantine_autonomy: Autonomy | None = None
    #: Agent IDs (without version) this agent may hand work off to. Empty means none: a
    #: hand-off is an owner-approved property of the delegating agent's contract.
    may_delegate_to: frozenset[str] = frozenset()

    @property
    def principal_id(self) -> str:
        return f"agent:{self.agent_id}@{self.version}"

    @property
    def key_thumbprint(self) -> str:
        return jwk_thumbprint(self.public_jwk)

    @property
    def active(self) -> bool:
        return self.retired_at is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "principal_id": self.principal_id,
            "owner": self.owner,
            "model_ref": self.model_ref,
            "allowed_tools": sorted(self.allowed_tools),
            "max_autonomy": self.max_autonomy.value,
            "risk_tier": self.risk_tier,
            "eval_status": self.eval_status.value,
            "evals": list(self.evals),
            "retired_at": self.retired_at.isoformat() if self.retired_at else None,
            "quarantined": self.quarantined,
            "may_delegate_to": sorted(self.may_delegate_to),
            "key_thumbprint": self.key_thumbprint,
        }


@dataclass(frozen=True, slots=True)
class TriggerRegistration:
    """A registered event or schedule source with an owner-approved policy envelope."""

    trigger_id: str
    owner: str
    envelope: frozenset[str]
    approved_by: str
    approved_at: datetime
    description: str = ""
    entitlements: frozenset[str] = frozenset()
    enabled: bool = True
    #: Agents this trigger may start; empty means any registered agent.
    agents: frozenset[str] = field(default_factory=frozenset)

    @property
    def principal_id(self) -> str:
        return f"trigger:{self.trigger_id}"


RegistryListener = Callable[[str, dict[str, Any]], None]


class AgentRegistry:
    def __init__(self, inventory: Inventory, listener: RegistryListener | None = None) -> None:
        self._inventory = inventory
        self._agents: dict[str, AgentContract] = {}
        self._triggers: dict[str, TriggerRegistration] = {}
        self._lock = threading.RLock()
        self._listener = listener

    # -- agents -----------------------------------------------------------------------------

    def register(self, contract: AgentContract) -> AgentContract:
        owner = self._inventory.find_principal(contract.owner)
        if owner is None or owner.kind is not PrincipalKind.HUMAN:
            raise RegistryError(f"agent owner {contract.owner!r} must be a known human principal")
        if not contract.allowed_tools:
            raise RegistryError("an agent contract must list at least one tool")
        if "d" in contract.public_jwk:
            raise RegistryError("register the agent's public key only")
        with self._lock:
            if contract.principal_id in self._agents:
                raise RegistryError(f"{contract.principal_id} is already registered")
            self._agents[contract.principal_id] = contract
        self._emit("agent.registered", contract.to_dict())
        return contract

    def get(self, principal_id: str) -> AgentContract:
        with self._lock:
            try:
                return self._agents[principal_id]
            except KeyError:
                raise UnknownAgentError(principal_id) from None

    def agents(self) -> list[AgentContract]:
        with self._lock:
            return list(self._agents.values())

    def retire(self, principal_id: str, at: datetime) -> AgentContract:
        return self._update(principal_id, "agent.retired", retired_at=at)

    def quarantine(self, principal_id: str, reason: str) -> AgentContract:
        """Drop the agent to read-only. Callers must also revoke its active tokens."""
        with self._lock:
            current = self.get(principal_id)
            if current.quarantined:
                return current
            updated = replace(
                current,
                quarantined=True,
                pre_quarantine_autonomy=current.max_autonomy,
                max_autonomy=Autonomy.READ,
            )
            self._agents[principal_id] = updated
        self._emit("agent.quarantined", {**updated.to_dict(), "reason": reason})
        return updated

    def restore(self, principal_id: str, approved_by: str) -> AgentContract:
        """Lift a quarantine. Only the agent's owner may approve the restore."""
        with self._lock:
            current = self.get(principal_id)
            if not current.quarantined:
                raise RegistryError(f"{principal_id} is not quarantined")
            if approved_by != current.owner:
                raise RegistryError("only the agent owner can approve a restore")
            updated = replace(
                current,
                quarantined=False,
                max_autonomy=current.pre_quarantine_autonomy or Autonomy.READ,
                pre_quarantine_autonomy=None,
            )
            self._agents[principal_id] = updated
        self._emit("agent.restored", {**updated.to_dict(), "approved_by": approved_by})
        return updated

    def _update(self, principal_id: str, event: str, **changes: Any) -> AgentContract:
        with self._lock:
            updated = replace(self.get(principal_id), **changes)
            self._agents[principal_id] = updated
        self._emit(event, updated.to_dict())
        return updated

    # -- triggers ---------------------------------------------------------------------------

    def register_trigger(self, trigger: TriggerRegistration) -> TriggerRegistration:
        owner = self._inventory.find_principal(trigger.owner)
        if owner is None or owner.kind is not PrincipalKind.HUMAN:
            raise RegistryError(f"trigger owner {trigger.owner!r} must be a known human principal")
        if trigger.approved_by != trigger.owner:
            raise RegistryError("the trigger's owner must approve its envelope at registration")
        if not trigger.envelope:
            raise RegistryError("a trigger envelope must list at least one tool")
        with self._lock:
            self._triggers[trigger.trigger_id] = trigger
        self._emit(
            "trigger.registered",
            {
                "trigger_id": trigger.trigger_id,
                "owner": trigger.owner,
                "envelope": sorted(trigger.envelope),
                "approved_by": trigger.approved_by,
            },
        )
        return trigger

    def trigger(self, trigger_id: str) -> TriggerRegistration:
        with self._lock:
            try:
                return self._triggers[trigger_id]
            except KeyError:
                raise UnknownAgentError(f"trigger:{trigger_id}") from None

    def disable_trigger(self, trigger_id: str) -> None:
        with self._lock:
            self._triggers[trigger_id] = replace(self.trigger(trigger_id), enabled=False)
        self._emit("trigger.disabled", {"trigger_id": trigger_id})

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        if self._listener is not None:
            self._listener(event, payload)
