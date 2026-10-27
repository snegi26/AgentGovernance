# SPDX-License-Identifier: Apache-2.0
"""Tool backends: what the gateway forwards an allowed call to.

Real deployments forward to MCP tool servers, SAP OData services, Entra Graph and so on.
:class:`InMemoryBackend` stands in for them in tests and the demo; it applies grants to the
inventory so provisioning visibly records the decision that authorized it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any, Protocol

from agent_governance.core import new_id
from agent_governance.model import Assignment, Inventory
from agent_governance.policy.tools import ToolSpec


@dataclass(frozen=True, slots=True)
class CallContext:
    agent: str
    delegator: str
    session_id: str
    plan_id: str
    decision_id: str


class ToolBackend(Protocol):
    def invoke(
        self, tool: ToolSpec, arguments: Mapping[str, Any], context: CallContext
    ) -> dict[str, Any]: ...


class ToolBackendError(RuntimeError):
    pass


Handler = Callable[[Mapping[str, Any], CallContext], dict[str, Any]]


class InMemoryBackend:
    def __init__(self, inventory: Inventory) -> None:
        self.inventory = inventory
        self.calls: list[tuple[str, dict[str, Any], CallContext]] = []
        self._handlers: dict[str, Handler] = {
            "iag.submit_request": self._submit_request,
            "iag.grant_assignment": self._grant_assignment,
            "catalog.search_roles": self._search_roles,
        }

    def register(self, tool_id: str, handler: Handler) -> None:
        self._handlers[tool_id] = handler

    def invoke(
        self, tool: ToolSpec, arguments: Mapping[str, Any], context: CallContext
    ) -> dict[str, Any]:
        self.calls.append((tool.tool_id, dict(arguments), context))
        handler = self._handlers.get(tool.tool_id)
        if handler is not None:
            return handler(arguments, context)
        return {"status": "ok", "tool": tool.tool_id, "reference": new_id("ref")}

    def _submit_request(self, args: Mapping[str, Any], ctx: CallContext) -> dict[str, Any]:
        return {"status": "submitted", "request_id": new_id("req"), "decision_id": ctx.decision_id}

    def _grant_assignment(self, args: Mapping[str, Any], ctx: CallContext) -> dict[str, Any]:
        target = str(args.get("target") or ctx.delegator)
        end = args.get("end_date")
        granted = []
        for role_id in args.get("roles", []):
            role = self.inventory.role(str(role_id))
            self.inventory.add_assignments(
                [
                    Assignment(
                        target,
                        role.role_id,
                        role.system,
                        valid_to=date.fromisoformat(str(end)) if end else None,
                        granted_by_decision_id=ctx.decision_id,
                    )
                ]
            )
            granted.append(role.role_id)
        return {
            "status": "granted",
            "target": target,
            "roles": granted,
            "decision_id": ctx.decision_id,
        }

    def _search_roles(self, args: Mapping[str, Any], ctx: CallContext) -> dict[str, Any]:
        query = str(args.get("query", "")).lower()
        return {
            "roles": [
                {"role_id": r.role_id, "system": r.system, "description": r.description}
                for r in self.inventory.roles()
                if query in r.role_id.lower() or query in r.description.lower()
            ]
        }
