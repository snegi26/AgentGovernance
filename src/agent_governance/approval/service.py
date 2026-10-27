# SPDX-License-Identifier: Apache-2.0
"""Human approvals that are signed, expiring and bound to one exact call payload.

Agents prepare; humans commit. When the gateway parks a call it opens an
:class:`ApprovalTask` keyed by the call's ``call_hash``. Each approver signs an approval over
that hash; the agent resubmits the *same* call with the approvals attached, and the gateway
checks that the signatures are valid, unexpired, for this hash, from distinct named people who
hold every role the tier requires, and that none of them is the delegator.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_governance.approval.tiers import ApprovalTier, ApproverRole
from agent_governance.core import Clock, SystemClock, new_id
from agent_governance.evidence.record import EvidenceKind
from agent_governance.evidence.store import EvidenceSink
from agent_governance.model import Inventory

APPROVAL_ISSUER = "agent-governance/approvals"


class ApprovalError(ValueError):
    pass


class TaskStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ApprovalTask:
    task_id: str
    call_hash: str
    tier: ApprovalTier
    tool_id: str
    delegator: str
    summary: Mapping[str, Any]
    created_at: datetime
    expires_at: datetime
    status: TaskStatus = TaskStatus.PENDING
    approvals: dict[ApproverRole, str] = field(default_factory=dict)
    approvers: dict[ApproverRole, str] = field(default_factory=dict)

    @property
    def outstanding_roles(self) -> frozenset[ApproverRole]:
        return self.tier.required_roles - set(self.approvals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "call_hash": self.call_hash,
            "tier": self.tier.value,
            "tool_id": self.tool_id,
            "delegator": self.delegator,
            "summary": dict(self.summary),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status.value,
            "required_roles": sorted(r.value for r in self.tier.required_roles),
            "outstanding_roles": sorted(r.value for r in self.outstanding_roles),
            "approvers": {r.value: p for r, p in self.approvers.items()},
            "approvals": list(self.approvals.values()),
        }


class ApproverDirectory:
    """Who may approve in which role. Line managers come from the inventory's ``manager_id``."""

    def __init__(
        self, inventory: Inventory, grants: Mapping[ApproverRole, Iterable[str]] | None = None
    ) -> None:
        self._inventory = inventory
        self._grants: dict[ApproverRole, set[str]] = {r: set(p) for r, p in (grants or {}).items()}

    def grant(self, role: ApproverRole, principal_id: str) -> None:
        self._grants.setdefault(role, set()).add(principal_id)

    def holds(self, principal_id: str, role: ApproverRole, *, delegator: str) -> bool:
        if role == ApproverRole.LINE_MANAGER:
            subject = self._inventory.find_principal(delegator)
            return subject is not None and subject.manager_id == principal_id
        return principal_id in self._grants.get(role, set())


@dataclass(frozen=True, slots=True)
class ApprovalCheck:
    valid: bool
    approvers: tuple[str, ...] = ()
    approval_ids: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()


class ApprovalService:
    def __init__(
        self,
        *,
        tenant: str,
        signing_key: Ed25519PrivateKey,
        directory: ApproverDirectory,
        evidence: EvidenceSink,
        clock: Clock | None = None,
        approval_ttl: timedelta = timedelta(hours=24),
        task_ttl: timedelta = timedelta(days=7),
    ) -> None:
        self.tenant = tenant
        self._key = signing_key
        self.directory = directory
        self.evidence = evidence
        self.clock = clock or SystemClock()
        self.approval_ttl = approval_ttl
        self.task_ttl = task_ttl
        self._tasks: dict[str, ApprovalTask] = {}
        self._by_hash: dict[str, str] = {}
        self._lock = threading.RLock()

    # -- tasks ------------------------------------------------------------------------------

    def open_task(
        self,
        *,
        call_hash: str,
        tier: ApprovalTier,
        tool_id: str,
        delegator: str,
        summary: Mapping[str, Any],
    ) -> ApprovalTask:
        """Open (or return the open) task for this payload. Idempotent per ``call_hash``."""
        if tier is ApprovalTier.NONE:
            raise ApprovalError("tier NONE needs no approval task")
        now = self.clock.now()
        with self._lock:
            existing = self._by_hash.get(call_hash)
            if existing is not None:
                task = self._tasks[existing]
                if (
                    task.status is TaskStatus.PENDING
                    and task.expires_at > now
                    and task.tier.rank >= tier.rank
                ):
                    return task
            task = ApprovalTask(
                task_id=new_id("apt"),
                call_hash=call_hash,
                tier=tier,
                tool_id=tool_id,
                delegator=delegator,
                summary=summary,
                created_at=now,
                expires_at=now + self.task_ttl,
            )
            self._tasks[task.task_id] = task
            self._by_hash[call_hash] = task.task_id
            return task

    def task(self, task_id: str) -> ApprovalTask:
        with self._lock:
            try:
                return self._tasks[task_id]
            except KeyError:
                raise ApprovalError(f"unknown approval task {task_id!r}") from None

    def task_for(self, call_hash: str) -> ApprovalTask | None:
        with self._lock:
            task_id = self._by_hash.get(call_hash)
            return self._tasks[task_id] if task_id else None

    def pending(self) -> list[ApprovalTask]:
        now = self.clock.now()
        with self._lock:
            return [
                t
                for t in self._tasks.values()
                if t.status is TaskStatus.PENDING and t.expires_at > now
            ]

    # -- decisions ----------------------------------------------------------------------------

    def approve(self, task_id: str, approver: str, role: ApproverRole | str) -> str:
        """Record a named approval and return the signed approval token."""
        try:
            role = ApproverRole(role)
        except ValueError:
            raise ApprovalError(f"unknown approver role {role!r}") from None
        now = self.clock.now()
        with self._lock:
            task = self.task(task_id)
            if task.status is not TaskStatus.PENDING or task.expires_at <= now:
                raise ApprovalError(f"task {task_id} is not open")
            if role not in task.tier.required_roles:
                raise ApprovalError(f"tier {task.tier} does not take a {role} approval")
            if role in task.approvals:
                raise ApprovalError(f"{role} has already approved")
            if approver == task.delegator:
                raise ApprovalError("the delegating principal cannot approve its own request")
            if approver in task.approvers.values():
                raise ApprovalError("one person cannot approve in two roles")
            if not self.directory.holds(approver, role, delegator=task.delegator):
                raise ApprovalError(f"{approver} does not hold approver role {role}")
            approval_id = new_id("apr")
            token = jwt.encode(
                {
                    "iss": APPROVAL_ISSUER,
                    "approval_id": approval_id,
                    "task_id": task.task_id,
                    "call_hash": task.call_hash,
                    "tier": task.tier.value,
                    "role": role.value,
                    "approver": approver,
                    "delegator": task.delegator,
                    "iat": int(now.timestamp()),
                    "exp": int((now + self.approval_ttl).timestamp()),
                },
                self._key,
                algorithm="EdDSA",
            )
            task.approvals[role] = token
            task.approvers[role] = approver
            if not task.outstanding_roles:
                task.status = TaskStatus.APPROVED
        self.evidence.append(
            self.tenant,
            EvidenceKind.APPROVAL,
            actor={"agent": None, "delegator": task.delegator},
            verdict="approved",
            approver=approver,
            inputs_hash=task.call_hash,
            details={
                "task_id": task.task_id,
                "approval_id": approval_id,
                "role": role.value,
                "tier": task.tier.value,
            },
        )
        return token

    def reject(self, task_id: str, approver: str, reason: str) -> ApprovalTask:
        with self._lock:
            task = self.task(task_id)
            if task.status is not TaskStatus.PENDING:
                raise ApprovalError(f"task {task_id} is not open")
            task.status = TaskStatus.REJECTED
        self.evidence.append(
            self.tenant,
            EvidenceKind.APPROVAL,
            actor={"agent": None, "delegator": task.delegator},
            verdict="rejected",
            approver=approver,
            inputs_hash=task.call_hash,
            details={"task_id": task.task_id, "reason": reason},
        )
        return task

    # -- verification (used by the gateway) ---------------------------------------------------

    def verify(
        self, tokens: Sequence[str], *, call_hash: str, tier: ApprovalTier, delegator: str
    ) -> ApprovalCheck:
        if tier is ApprovalTier.NONE:
            return ApprovalCheck(valid=True)
        now = int(self.clock.now().timestamp())
        problems: list[str] = []
        covered: dict[ApproverRole, str] = {}
        ids: list[str] = []
        for token in tokens:
            try:
                claims = jwt.decode(
                    token,
                    self._key.public_key(),
                    algorithms=["EdDSA"],
                    issuer=APPROVAL_ISSUER,
                    options={
                        "require": ["exp", "call_hash", "approver", "role"],
                        "verify_exp": False,
                    },
                )
            except jwt.PyJWTError as exc:
                problems.append(f"invalid approval signature: {exc}")
                continue
            if int(claims["exp"]) <= now:
                problems.append(f"approval {claims.get('approval_id')} expired")
                continue
            if claims["call_hash"] != call_hash:
                problems.append(f"approval {claims.get('approval_id')} is for a different payload")
                continue
            try:
                role = ApproverRole(claims["role"])
            except ValueError:
                problems.append("unknown approver role")
                continue
            approver = str(claims["approver"])
            if approver == delegator:
                problems.append("self-approval is not accepted")
                continue
            if not self.directory.holds(approver, role, delegator=delegator):
                problems.append(f"{approver} no longer holds {role}")
                continue
            if approver in covered.values() and covered.get(role) != approver:
                problems.append("one person cannot approve in two roles")
                continue
            covered[role] = approver
            ids.append(str(claims.get("approval_id")))
        task = self.task_for(call_hash)
        if task is not None and task.status is TaskStatus.REJECTED:
            problems.append("the approval task was rejected")
        missing = tier.required_roles - set(covered)
        if missing:
            problems.append("missing approvals: " + ", ".join(sorted(r.value for r in missing)))
        valid = not missing and not (task is not None and task.status is TaskStatus.REJECTED)
        return ApprovalCheck(
            valid=valid,
            approvers=tuple(covered[r] for r in sorted(covered)),
            approval_ids=tuple(ids),
            problems=tuple(problems),
        )
