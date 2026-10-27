# SPDX-License-Identifier: Apache-2.0
"""The policy enforcement gateway: the only path from an agent to a target system.

Per call, in order (spec, "Per-call evaluation"):

1. verify the DPoP-bound token; resolve ``sub``, the ``act`` chain, ``session_id``, ``plan_id``;
2. check the tool is in the token scope and the agent contract's ``allowed_tools``;
3. evaluate Cedar with principal = agent, ``context.delegator`` = the innermost human/trigger;
4. for write tools, run session SoD and/or request simulation;
5. if approval is required, park the call behind an approval task; resume only on signed
   approvals whose ``call_hash`` matches this exact payload;
6. write the decision record to the evidence store *before* forwarding.

Failure behaviour is fail closed: if the policy engine, SoD engine or evidence store is
unavailable, writes are denied and reads are served only from cache with ``stale = True``.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from enum import StrEnum
from typing import Any

from agent_governance.approval.service import ApprovalCheck, ApprovalService
from agent_governance.approval.tiers import (
    BULK_REVOKE_THRESHOLD,
    LOW_RISK_MAX_DAYS,
    ApprovalTier,
    strictest,
)
from agent_governance.core import Clock, SystemClock, digest
from agent_governance.evidence.record import EvidenceKind, EvidenceRecord
from agent_governance.evidence.store import EvidenceSink, EvidenceUnavailableError
from agent_governance.gateway.backends import CallContext, ToolBackend
from agent_governance.gateway.untrusted import (
    POSSIBLE_INJECTION,
    PRIVILEGED_PROFILE,
    scan_arguments,
)
from agent_governance.identity.dpop import DpopError, DpopVerifier
from agent_governance.identity.registry import (
    AgentContract,
    AgentRegistry,
    Autonomy,
    UnknownAgentError,
)
from agent_governance.identity.sts import AccessClaims, InvalidTokenError, TokenService
from agent_governance.model import Inventory, PrincipalKind, UnknownEntityError
from agent_governance.policy.engine import (
    DelegatorContext,
    PolicyEngine,
    PolicyEngineError,
    PolicyInput,
)
from agent_governance.policy.tools import ActionClass, ToolCatalog, ToolSpec
from agent_governance.sod.engine import SodEngine
from agent_governance.sod.ruleset import RiskLevel
from agent_governance.sod.session import SessionChecker, SessionDecision, SessionStep

#: Argument names that assert a compliance verdict and must cite an engine ``result_ref``.
VERDICT_FIELDS = ("compliant", "sod_clean", "sod_result", "verdict", "risk_score")


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool_id: str
    arguments: Mapping[str, Any]
    access_token: str
    dpop_proof: str | None
    htu: str
    htm: str = "POST"
    approvals: Sequence[str] = ()


@dataclass(frozen=True, slots=True)
class GatewayResult:
    verdict: Verdict
    reason: str
    tool_id: str
    evidence_id: str | None = None
    call_hash: str | None = None
    approval_task_id: str | None = None
    tier: ApprovalTier = ApprovalTier.NONE
    result: Mapping[str, Any] | None = None
    stale: bool = False
    flags: tuple[str, ...] = ()
    sod_result_ref: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "tool_id": self.tool_id,
            "evidence_id": self.evidence_id,
            "call_hash": self.call_hash,
            "approval_task_id": self.approval_task_id,
            "tier": self.tier.value,
            "result": dict(self.result) if self.result is not None else None,
            "stale": self.stale,
            "flags": list(self.flags),
            "sod_result_ref": self.sod_result_ref,
            "details": dict(self.details),
        }


class _Denied(Exception):
    def __init__(self, reason: str, **details: Any) -> None:
        super().__init__(reason)
        self.reason = reason
        self.details = details


class DependencyUnavailableError(RuntimeError):
    pass


@dataclass
class _SodOutcome:
    verdict: SessionDecision = SessionDecision.ALLOW
    tier: ApprovalTier = ApprovalTier.NONE
    result_ref: str | None = None
    step: SessionStep | None = None
    summary: dict[str, Any] = field(default_factory=dict)


class ReadCache:
    """Last good result per (tool, arguments, delegator), served only during outages."""

    def __init__(self, capacity: int = 10_000) -> None:
        self._data: OrderedDict[str, Mapping[str, Any]] = OrderedDict()
        self._capacity = capacity
        self._lock = threading.Lock()

    @staticmethod
    def key(tool_id: str, arguments: Mapping[str, Any], delegator: str) -> str:
        return digest({"tool": tool_id, "args": dict(arguments), "delegator": delegator})

    def get(self, key: str) -> Mapping[str, Any] | None:
        with self._lock:
            return self._data.get(key)

    def put(self, key: str, value: Mapping[str, Any]) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)


class Gateway:
    def __init__(
        self,
        *,
        tenant: str,
        tokens: TokenService,
        dpop: DpopVerifier,
        registry: AgentRegistry,
        inventory: Inventory,
        tools: ToolCatalog,
        policy: PolicyEngine,
        sod: SodEngine,
        session: SessionChecker,
        approvals: ApprovalService,
        evidence: EvidenceSink,
        backend: ToolBackend,
        clock: Clock | None = None,
        read_cache: ReadCache | None = None,
    ) -> None:
        self.tenant = tenant
        self.tokens = tokens
        self.dpop = dpop
        self.registry = registry
        self.inventory = inventory
        self.tools = tools
        self.policy = policy
        self.sod = sod
        self.session = session
        self.approvals = approvals
        self.evidence = evidence
        self.backend = backend
        self.clock = clock or SystemClock()
        self.read_cache = read_cache or ReadCache()
        # Serialises check -> forward -> record per delegator, so two concurrent calls cannot
        # both pass session SoD before either is recorded.
        self._delegator_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    # -- entry point ---------------------------------------------------------------------------

    def handle(self, call: ToolCall) -> GatewayResult:
        tool = self.tools.find(call.tool_id)
        if tool is None:
            return self._refuse(call, None, None, "unknown tool")
        try:
            claims = self._authenticate(call, tool)
            agent = self._agent(claims, tool)
        except _Denied as denied:
            return self._refuse(call, tool, None, denied.reason, **denied.details)
        with self._lock_for(claims.delegation.root):
            return self._decide(call, tool, claims, agent)

    # -- steps 1-2: identity ---------------------------------------------------------------------

    def _authenticate(self, call: ToolCall, tool: ToolSpec) -> AccessClaims:
        try:
            claims = self.tokens.verify_access_token(call.access_token, audience=tool.server)
        except InvalidTokenError as exc:
            raise _Denied(f"invalid token: {exc}") from exc
        try:
            self.dpop.verify(
                call.dpop_proof,
                htm=call.htm,
                htu=call.htu,
                access_token=call.access_token,
                expected_jkt=claims.jkt,
            )
        except DpopError as exc:
            raise _Denied(f"DPoP check failed: {exc}", agent=claims.subject) from exc
        if claims.tenant != self.tenant:
            raise _Denied("token is for another tenant", agent=claims.subject)
        return claims

    def _agent(self, claims: AccessClaims, tool: ToolSpec) -> AgentContract:
        try:
            agent = self.registry.get(claims.subject)
        except UnknownAgentError as exc:
            raise _Denied("unregistered agent", agent=claims.subject) from exc
        if not agent.active:
            raise _Denied("agent is retired", agent=claims.subject)
        if tool.tool_id not in claims.scope:
            raise _Denied("tool not in token scope", agent=claims.subject)
        if tool.tool_id not in agent.allowed_tools:
            raise _Denied("tool not in agent contract", agent=claims.subject)
        return agent

    def _delegator(self, claims: AccessClaims) -> DelegatorContext:
        root = claims.delegation.root
        if claims.delegation.root_kind is PrincipalKind.TRIGGER:
            try:
                trigger = self.registry.trigger(root.removeprefix("trigger:"))
            except UnknownAgentError as exc:
                raise _Denied("trigger is no longer registered") from exc
            if not trigger.enabled:
                raise _Denied("trigger is disabled")
            entitlements = trigger.entitlements | trigger.envelope
            return DelegatorContext("trigger", root, frozenset(entitlements))
        principal = self.inventory.find_principal(root)
        if principal is None or not principal.active:
            raise _Denied("delegating principal is not active")
        return DelegatorContext("human", root, principal.entitlements)

    # -- steps 3-6 ---------------------------------------------------------------------------

    def _decide(
        self, call: ToolCall, tool: ToolSpec, claims: AccessClaims, agent: AgentContract
    ) -> GatewayResult:
        actor = {"agent": agent.principal_id, "delegator": claims.delegation.root}
        call_hash = self.call_hash(call, claims)
        flags = scan_arguments(call.arguments, tool.untrusted_fields)
        base = {"actor": actor, "claims": claims, "call_hash": call_hash, "flags": flags}
        try:
            delegator = self._delegator(claims)
            self._validate_engine_refs(tool, call.arguments)
            sod = (
                self._sod(tool, call, claims, actor)
                if tool.action_class.is_write
                else _SodOutcome()
            )
            tier = self._tier(tool, agent, call.arguments, sod, flags)
            check = self.approvals.verify(
                call.approvals, call_hash=call_hash, tier=tier, delegator=claims.delegation.root
            )
            decision = self.policy.evaluate(
                PolicyInput(
                    agent=agent,
                    tool=tool,
                    delegator=delegator,
                    token_scope=claims.scope,
                    call_hash=call_hash,
                    approval_valid=check.valid and tier is not ApprovalTier.NONE,
                    approval_hash=call_hash if check.valid else "",
                    approval_required=tier is not ApprovalTier.NONE,
                    sod_verdict=sod.verdict.value,
                    flags=flags,
                )
            )
        except _Denied as denied:
            return self._refuse(
                call,
                tool,
                claims,
                denied.reason,
                call_hash=call_hash,
                flags=flags,
                **denied.details,
            )
        except (PolicyEngineError, DependencyUnavailableError, EvidenceUnavailableError) as exc:
            return self._dependency_failure(call, tool, base, exc)

        verdict = Verdict(decision.verdict.value)
        task_id = None
        if verdict is Verdict.REQUIRE_APPROVAL:
            task = self.approvals.open_task(
                call_hash=call_hash,
                tier=tier,
                tool_id=tool.tool_id,
                delegator=claims.delegation.root,
                summary={
                    "tool": tool.tool_id,
                    "arguments": dict(call.arguments),
                    "agent": agent.principal_id,
                    "plan_id": claims.plan_id,
                    "sod": sod.summary,
                    "flags": flags,
                },
            )
            task_id = task.task_id
        reason = self._reason(verdict, decision.determining_policies, sod, check)
        try:
            record = self.evidence.append(
                self.tenant,
                EvidenceKind.GATEWAY_DECISION,
                actor=actor,
                verdict=verdict.value,
                session_id=claims.session_id,
                plan_id=claims.plan_id,
                inputs_hash=call_hash,
                ruleset_version=self.sod.ruleset.version if tool.action_class.is_write else None,
                model_ref=agent.model_ref,
                approver=",".join(check.approvers) or None,
                flags=tuple(flags),
                details={
                    "tool": tool.tool_id,
                    "action_class": tool.action_class.value,
                    "tier": tier.value,
                    "policy": decision.to_dict(),
                    "sod_result_ref": sod.result_ref,
                    "approval_task_id": task_id,
                    "approval_ids": list(check.approval_ids),
                    "approval_problems": list(check.problems),
                    "jti": claims.jti,
                    "act_chain": list(claims.delegation.chain),
                    "reason": reason,
                },
            )
        except EvidenceUnavailableError as exc:
            return self._dependency_failure(call, tool, base, exc)

        result = GatewayResult(
            verdict=verdict,
            reason=reason,
            tool_id=tool.tool_id,
            evidence_id=record.record_id,
            call_hash=call_hash,
            approval_task_id=task_id,
            tier=tier,
            flags=tuple(flags),
            sod_result_ref=sod.result_ref,
            details={"policy": decision.to_dict(), "sod": sod.summary},
        )
        if verdict is not Verdict.ALLOW:
            return result
        return self._forward(call, tool, claims, record=record, sod=sod, result=result)

    def _forward(
        self,
        call: ToolCall,
        tool: ToolSpec,
        claims: AccessClaims,
        *,
        record: EvidenceRecord,
        sod: _SodOutcome,
        result: GatewayResult,
    ) -> GatewayResult:
        context = CallContext(
            agent=claims.subject,
            delegator=claims.delegation.root,
            session_id=claims.session_id,
            plan_id=claims.plan_id,
            decision_id=record.record_id,
        )
        try:
            output = self.backend.invoke(tool, call.arguments, context)
        except Exception as exc:  # the target system failed; the decision record stands
            return replace(
                result, reason=f"allowed, but the tool failed: {exc}", result={"error": str(exc)}
            )
        if sod.step is not None:
            self.session.record(sod.step)
        if tool.action_class is ActionClass.READ:
            self.read_cache.put(
                ReadCache.key(tool.tool_id, call.arguments, claims.delegation.root), output
            )
        return replace(result, result=output)

    # -- SoD ------------------------------------------------------------------------------------

    def _sod(
        self, tool: ToolSpec, call: ToolCall, claims: AccessClaims, actor: dict[str, str]
    ) -> _SodOutcome:
        outcome = _SodOutcome()
        results: list[dict[str, Any]] = []
        try:
            if tool.sod is not None:
                step = SessionStep(
                    system=tool.sod.system,
                    action=tool.sod.action,
                    session_id=claims.session_id,
                    plan_id=claims.plan_id,
                    delegator=claims.delegation.root,
                    agent=claims.subject,
                    object_keys={
                        key: str(call.arguments[arg])
                        for arg, key in tool.sod.object_keys.items()
                        if call.arguments.get(arg) not in (None, "")
                    },
                )
                session = self.session.check(step)
                outcome.step = step
                outcome.verdict = session.decision
                if session.decision is SessionDecision.REQUIRE_APPROVAL:
                    outcome.tier = ApprovalTier.HIGH_RISK_WRITE
                results.append(session.to_dict())
                outcome.summary["session"] = {
                    "decision": session.decision.value,
                    "risks": [v.risk_id for v in session.violations],
                }
            if tool.request_check:
                self._request_check(call.arguments, claims, outcome, results)
        except _Denied:
            raise
        except (UnknownEntityError, KeyError, ValueError, TypeError) as exc:
            raise _Denied(f"cannot evaluate SoD for this request: {exc}") from exc
        except Exception as exc:
            raise DependencyUnavailableError(f"SoD engine unavailable: {exc}") from exc
        record = self.evidence.append(
            self.tenant,
            EvidenceKind.SOD_VERDICT,
            actor=actor,
            verdict=outcome.verdict.value,
            session_id=claims.session_id,
            plan_id=claims.plan_id,
            ruleset_version=self.sod.ruleset.version,
            details={
                "ruleset_digest": self.sod.ruleset.digest,
                "tool": tool.tool_id,
                "results": results,
            },
        )
        outcome.result_ref = record.record_id
        outcome.summary["result_ref"] = record.record_id
        return outcome

    def _request_check(
        self,
        args: Mapping[str, Any],
        claims: AccessClaims,
        outcome: _SodOutcome,
        results: list[dict[str, Any]],
    ) -> None:
        target = str(args.get("target") or claims.delegation.root)
        roles = [str(r) for r in args.get("roles", [])]
        if not roles:
            raise _Denied("request names no roles")
        simulation = self.sod.simulate(target, add_roles=roles)
        results.append(simulation.to_dict())
        added = simulation.added
        unmitigated_severe = [
            v
            for v in added
            if not v.mitigated
            and v.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            and not v.critical
        ]
        outcome.summary["simulation"] = {
            "target": target,
            "added": [v.risk_id for v in added],
            "unmitigated": [v.risk_id for v in added if not v.mitigated],
        }
        if unmitigated_severe:
            outcome.verdict = SessionDecision.DENY
            return
        critical_role = any(self.inventory.role(r).critical for r in roles)
        if added or critical_role:
            outcome.verdict = SessionDecision.REQUIRE_APPROVAL
            outcome.tier = strictest(outcome.tier, ApprovalTier.HIGH_RISK_WRITE)
            return
        end = args.get("end_date")
        today = self.clock.now().date()
        if not end or (date.fromisoformat(str(end)) - today).days > LOW_RISK_MAX_DAYS:
            outcome.tier = strictest(outcome.tier, ApprovalTier.HIGH_RISK_WRITE)
            outcome.summary["duration"] = "open-ended or longer than 30 days"
        else:
            outcome.tier = strictest(outcome.tier, ApprovalTier.LOW_RISK_WRITE)

    # -- tiers and validation -------------------------------------------------------------------

    @staticmethod
    def _tier(
        tool: ToolSpec,
        agent: AgentContract,
        args: Mapping[str, Any],
        sod: _SodOutcome,
        flags: Sequence[str],
    ) -> ApprovalTier:
        if not tool.action_class.is_write:
            return ApprovalTier.NONE
        tiers = [tool.base_tier, sod.tier]
        if agent.max_autonomy is Autonomy.WRITE_WITH_APPROVAL:
            tiers.append(ApprovalTier.LOW_RISK_WRITE)
        if POSSIBLE_INJECTION in flags or PRIVILEGED_PROFILE in flags:
            tiers.append(ApprovalTier.HIGH_RISK_WRITE)
        if tool.bulk_field is not None:
            lines = args.get(tool.bulk_field) or []
            if isinstance(lines, list | tuple) and len(lines) > BULK_REVOKE_THRESHOLD:
                tiers.append(ApprovalTier.BULK_REVOKE)
        return strictest(*tiers)

    def _validate_engine_refs(self, tool: ToolSpec, args: Mapping[str, Any]) -> None:
        """Reject agent output that asserts a verdict without citing the engine result."""
        if tool.action_class is ActionClass.READ:
            return
        asserted = [f for f in VERDICT_FIELDS if f in args]
        if not asserted:
            return
        ref = args.get("sod_result_ref")
        if not ref:
            raise _Denied(f"output asserts {asserted} without an engine result_ref")
        get = getattr(self.evidence, "get", None)
        if get is None:
            return
        try:
            cited = get(str(ref))
        except KeyError as exc:
            raise _Denied(f"result_ref {ref!r} does not exist") from exc
        if cited.kind != EvidenceKind.SOD_VERDICT:
            raise _Denied(f"result_ref {ref!r} is not an SoD verdict")

    # -- refusals and outages -------------------------------------------------------------------

    def _refuse(
        self,
        call: ToolCall,
        tool: ToolSpec | None,
        claims: AccessClaims | None,
        reason: str,
        **details: Any,
    ) -> GatewayResult:
        call_hash = details.pop("call_hash", None)
        flags = tuple(details.pop("flags", ()))
        agent = details.pop("agent", claims.subject if claims else None)
        evidence_id = None
        try:
            record = self.evidence.append(
                self.tenant,
                EvidenceKind.GATEWAY_DECISION,
                actor={"agent": agent, "delegator": claims.delegation.root if claims else None},
                verdict=Verdict.DENY.value,
                session_id=claims.session_id if claims else None,
                plan_id=claims.plan_id if claims else None,
                inputs_hash=call_hash,
                flags=flags,
                details={"tool": call.tool_id, "reason": reason, **details},
            )
            evidence_id = record.record_id
        except EvidenceUnavailableError:
            pass  # denying is already the safe outcome
        return GatewayResult(
            verdict=Verdict.DENY,
            reason=reason,
            tool_id=call.tool_id,
            evidence_id=evidence_id,
            call_hash=call_hash,
            flags=flags,
        )

    def _dependency_failure(
        self, call: ToolCall, tool: ToolSpec, base: dict[str, Any], exc: Exception
    ) -> GatewayResult:
        claims: AccessClaims = base["claims"]
        if tool.action_class is ActionClass.READ:
            cached = self.read_cache.get(
                ReadCache.key(tool.tool_id, call.arguments, claims.delegation.root)
            )
            if cached is not None:
                return GatewayResult(
                    verdict=Verdict.ALLOW,
                    reason=f"served from cache: {exc}",
                    tool_id=tool.tool_id,
                    call_hash=base["call_hash"],
                    result=cached,
                    stale=True,
                )
        return self._refuse(
            call,
            tool,
            claims,
            f"fail closed: {exc}",
            call_hash=base["call_hash"],
            flags=base["flags"],
        )

    # -- helpers ------------------------------------------------------------------------------

    @staticmethod
    def call_hash(call: ToolCall, claims: AccessClaims) -> str:
        """The payload an approval signs: tool, arguments, agent, delegator, plan and audience."""
        return digest(
            {
                "tool": call.tool_id,
                "arguments": dict(call.arguments),
                "agent": claims.subject,
                "delegator": claims.delegation.root,
                "plan_id": claims.plan_id,
                "aud": claims.audience,
            }
        )

    def _lock_for(self, delegator: str) -> threading.Lock:
        with self._locks_guard:
            return self._delegator_locks.setdefault(delegator, threading.Lock())

    @staticmethod
    def _reason(
        verdict: Verdict, policies: Sequence[str], sod: _SodOutcome, check: ApprovalCheck
    ) -> str:
        if verdict is Verdict.ALLOW:
            return "allowed by " + ", ".join(policies) if policies else "allowed"
        if sod.verdict is SessionDecision.DENY:
            return "denied by SoD: " + ", ".join(
                sod.summary.get("session", {}).get("risks", [])
                + sod.summary.get("simulation", {}).get("unmitigated", [])
            )
        if verdict is Verdict.REQUIRE_APPROVAL:
            missing = [p for p in check.problems if p.startswith("missing")]
            return "approval required" + (f" ({missing[0]})" if missing else "")
        return "denied by " + (
            ", ".join(policies) if policies else "default deny (no permit matched)"
        )
