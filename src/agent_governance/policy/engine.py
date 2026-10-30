# SPDX-License-Identifier: Apache-2.0
"""Cedar policy evaluation for gateway decisions.

The engine evaluates twice when the first answer is *deny*: once with the approval actually
presented, and once with a hypothetical valid approval for this exact payload. If only the
second permits, the verdict is ``require_approval``; Cedar, not Python, decides whether an
approval would make the call acceptable.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any

import cedarpy

from agent_governance.identity.registry import AgentContract
from agent_governance.policy.tools import ActionClass, ToolSpec


class PolicyVerdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class PolicyEngineError(RuntimeError):
    """The policy engine could not evaluate. Callers must fail closed."""


@dataclass(frozen=True, slots=True)
class DelegatorContext:
    kind: str
    principal_id: str
    entitlements: frozenset[str]


@dataclass(frozen=True, slots=True)
class PolicyInput:
    agent: AgentContract
    tool: ToolSpec
    delegator: DelegatorContext
    token_scope: frozenset[str]
    call_hash: str
    approval_valid: bool
    approval_hash: str
    approval_required: bool
    sod_verdict: str
    flags: Sequence[str] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    verdict: PolicyVerdict
    determining_policies: tuple[str, ...]
    policy_set: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "determining_policies": list(self.determining_policies),
            "policy_set": self.policy_set,
        }


def _annotated_ids(policies: str) -> dict[str, str]:
    """Map cedarpy's positional ids (policy0, ...) to ``@id`` annotations."""
    data = json.loads(cedarpy.policies_to_json_str(policies))
    out = {}
    for pid, body in data.get("staticPolicies", {}).items():
        out[pid] = body.get("annotations", {}).get("id", pid)
    return out


class PolicyEngine:
    def __init__(self, policies: str, name: str = "custom") -> None:
        self.policies = policies
        self.name = name
        try:
            self._ids = _annotated_ids(policies)
        except Exception as exc:  # cedarpy raises plain exceptions on parse errors
            raise PolicyEngineError(f"invalid Cedar policy set: {exc}") from exc

    @classmethod
    def default(cls) -> PolicyEngine:
        text = resources.files("agent_governance.policy").joinpath("policies/default.cedar")
        return cls(text.read_text(encoding="utf-8"), name="default")

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        p = Path(path)
        return cls(p.read_text(encoding="utf-8"), name=p.name)

    def evaluate(self, data: PolicyInput) -> PolicyDecision:
        first = self._authorize(data, data.approval_valid, data.approval_hash)
        if first[0]:
            return PolicyDecision(PolicyVerdict.ALLOW, first[1], self.name)
        if data.tool.action_class.is_write and not data.approval_valid:
            hypothetical = self._authorize(data, True, data.call_hash)
            if hypothetical[0]:
                return PolicyDecision(PolicyVerdict.REQUIRE_APPROVAL, first[1], self.name)
            # Report what would still block the call with an approval: that is the real cause.
            return PolicyDecision(PolicyVerdict.DENY, hypothetical[1], self.name)
        return PolicyDecision(PolicyVerdict.DENY, first[1], self.name)

    def _authorize(
        self, data: PolicyInput, approval_valid: bool, approval_hash: str
    ) -> tuple[bool, tuple[str, ...]]:
        request = {
            "principal": f'Agent::"{data.agent.principal_id}"',
            "action": f'Action::"{data.tool.tool_id}"',
            "resource": f'Resource::"{data.tool.server}/{data.tool.resource_type}"',
            "context": {
                "tool_id": data.tool.tool_id,
                "required_entitlement": data.tool.entitlement,
                "token_scope": sorted(data.token_scope),
                "call_hash": data.call_hash,
                "delegator": {
                    "kind": data.delegator.kind,
                    "id": data.delegator.principal_id,
                    "entitlements": sorted(data.delegator.entitlements),
                },
                "approval": {"valid": approval_valid, "payload_hash": approval_hash},
                "approval_required": data.approval_required,
                "sod": {"verdict": data.sod_verdict},
                "flags": list(data.flags),
            },
        }
        try:
            result = cedarpy.is_authorized(request, self.policies, self._entities(data))
        except Exception as exc:
            raise PolicyEngineError(str(exc)) from exc
        errors = list(result.diagnostics.errors)
        if errors:
            raise PolicyEngineError("; ".join(map(str, errors)))
        reasons = tuple(sorted(self._ids.get(r, r) for r in result.diagnostics.reasons))
        return result.decision == cedarpy.Decision.Allow, reasons

    @staticmethod
    def _entities(data: PolicyInput) -> list[dict[str, Any]]:
        classes = [
            {"uid": {"type": "Action", "id": f"class:{c.value}"}, "attrs": {}, "parents": []}
            for c in ActionClass
        ]
        return [
            {
                "uid": {"type": "Agent", "id": data.agent.principal_id},
                "attrs": {
                    "allowed_tools": sorted(data.agent.allowed_tools),
                    "max_autonomy": data.agent.effective_autonomy.value,
                    "quarantined": data.agent.quarantined,
                    "risk_tier": data.agent.risk_tier,
                },
                "parents": [],
            },
            {
                "uid": {"type": "Action", "id": data.tool.tool_id},
                "attrs": {},
                "parents": [{"type": "Action", "id": f"class:{data.tool.action_class.value}"}],
            },
            *classes,
        ]
