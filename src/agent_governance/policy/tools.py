# SPDX-License-Identifier: Apache-2.0
"""The tool catalogue: every tool an agent can call, its server, action class and SoD binding.

Tool IDs are the unit of authorization everywhere: token ``scope`` lists tool IDs, agent
contracts list tool IDs, and Cedar actions are tool IDs.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from agent_governance.approval.tiers import ApprovalTier


class ActionClass(StrEnum):
    READ = "read"
    DRAFT = "draft"
    WRITE = "write"
    GRANT = "grant"  # grants, role changes, firefighter activation
    REVOKE = "revoke"

    @property
    def is_write(self) -> bool:
        return self in (ActionClass.WRITE, ActionClass.GRANT, ActionClass.REVOKE)

    @property
    def autonomy_rank(self) -> int:
        """Minimum agent autonomy rank that may call a tool of this class."""
        return {"read": 0, "draft": 1}.get(self.value, 2)


@dataclass(frozen=True, slots=True)
class SodBinding:
    """Maps a write tool to the target-system action it executes, for session SoD.

    ``object_keys`` maps tool argument names to the rule set's join-key names.
    """

    system: str
    action: str
    object_keys: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    tool_id: str
    server: str
    action_class: ActionClass
    resource_type: str
    description: str = ""
    required_entitlement: str | None = None
    sod: SodBinding | None = None
    request_check: bool = False
    untrusted_fields: tuple[str, ...] = ()
    base_tier: ApprovalTier = ApprovalTier.NONE
    bulk_field: str | None = None

    @property
    def entitlement(self) -> str:
        """The delegator entitlement this tool requires; by default the tool ID itself."""
        return self.required_entitlement or self.tool_id


class UnknownToolError(LookupError):
    pass


class ToolCatalog:
    def __init__(self, tools: Iterable[ToolSpec]) -> None:
        self._tools: dict[str, ToolSpec] = {}
        for tool in tools:
            if tool.tool_id in self._tools:
                raise ValueError(f"duplicate tool {tool.tool_id}")
            self._tools[tool.tool_id] = tool

    def get(self, tool_id: str) -> ToolSpec:
        try:
            return self._tools[tool_id]
        except KeyError:
            raise UnknownToolError(tool_id) from None

    def find(self, tool_id: str) -> ToolSpec | None:
        return self._tools.get(tool_id)

    def tools(self) -> list[ToolSpec]:
        return list(self._tools.values())

    def servers(self) -> frozenset[str]:
        return frozenset(t.server for t in self._tools.values())

    def for_server(self, server: str) -> list[ToolSpec]:
        return [t for t in self._tools.values() if t.server == server]


_R, _D, _W, _G, _X = (
    ActionClass.READ,
    ActionClass.DRAFT,
    ActionClass.WRITE,
    ActionClass.GRANT,
    ActionClass.REVOKE,
)

#: Tools named in the spec's agent table, plus SAP business transactions for session SoD.
DEFAULT_TOOLS = ToolCatalog(
    [
        # Access governance (IAG)
        ToolSpec("catalog.search_roles", "iag", _R, "catalog", "Search the role catalogue"),
        ToolSpec("sod.simulate", "iag", _R, "sod", "What-if SoD simulation"),
        ToolSpec("sod.static", "iag", _R, "sod", "Static SoD check of a principal"),
        ToolSpec(
            "iag.draft_request",
            "iag",
            _D,
            "request",
            "Create an access request draft",
            untrusted_fields=("justification",),
        ),
        ToolSpec(
            "iag.submit_request",
            "iag",
            _W,
            "request",
            "Submit an access request",
            required_entitlement="request_access_self_or_reports",
            request_check=True,
            untrusted_fields=("justification",),
        ),
        ToolSpec(
            "iag.grant_assignment",
            "iag",
            _G,
            "assignment",
            "Provision a role assignment",
            required_entitlement="provision_access",
            request_check=True,
            base_tier=ApprovalTier.HIGH_RISK_WRITE,
        ),
        # Certification
        ToolSpec("review.list_items", "iag", _R, "review", "List certification items"),
        ToolSpec("usage.get", "iag", _R, "usage", "Role usage facts"),
        ToolSpec("review.draft_decision", "iag", _D, "review", "Draft a keep/revoke decision"),
        ToolSpec(
            "review.revoke",
            "iag",
            _X,
            "assignment",
            "Revoke certification lines",
            required_entitlement="certify_access",
            bulk_field="lines",
            base_tier=ApprovalTier.LOW_RISK_WRITE,
        ),
        # Role simulation
        ToolSpec("roles.get", "iag", _R, "role", "Read a role"),
        ToolSpec("roles.draft_change", "iag", _D, "role", "Draft a role change"),
        # Firefighter
        ToolSpec("ff.get_session", "iag", _R, "ff_session", "Read a firefighter session"),
        ToolSpec("ff.reason_code", "iag", _R, "ff_session", "Allowed actions for a reason code"),
        ToolSpec(
            "ff.activate",
            "iag",
            _G,
            "ff_session",
            "Activate emergency access",
            required_entitlement="firefighter_request",
            untrusted_fields=("reason",),
            base_tier=ApprovalTier.HIGH_RISK_WRITE,
        ),
        ToolSpec(
            "logs.get_changes",
            "s4",
            _R,
            "change_log",
            "Read change documents",
            untrusted_fields=("text",),
        ),
        ToolSpec("review.draft_finding", "iag", _D, "review", "Draft a review finding"),
        # Threat triage
        ToolSpec("alerts.list", "iag", _R, "alert", "List security alerts"),
        ToolSpec("alerts.correlate", "iag", _R, "alert", "Correlate alerts"),
        ToolSpec("playbook.template", "iag", _R, "playbook", "Playbook templates"),
        ToolSpec("case.draft", "iag", _D, "case", "Draft a case", untrusted_fields=("summary",)),
        # Agent anomaly monitor
        ToolSpec("trace.query", "gateway", _R, "trace", "Query agent traces"),
        ToolSpec("baseline.get", "gateway", _R, "baseline", "Agent behaviour baseline"),
        ToolSpec(
            "gateway.quarantine",
            "gateway",
            _W,
            "agent",
            "Quarantine an agent",
            required_entitlement="quarantine_agents",
        ),
        # SAP S/4HANA business transactions (session SoD)
        ToolSpec(
            "s4.vendor_create",
            "s4",
            _W,
            "vendor",
            "Create vendor (XK01)",
            sod=SodBinding("S4", "XK01", {"vendor_id": "vendor_id"}),
        ),
        ToolSpec(
            "s4.vendor_change",
            "s4",
            _W,
            "vendor",
            "Change vendor (XK02)",
            sod=SodBinding("S4", "XK02", {"vendor_id": "vendor_id"}),
        ),
        ToolSpec(
            "s4.invoice_post",
            "s4",
            _W,
            "invoice",
            "Enter vendor invoice (FB60)",
            untrusted_fields=("text",),
            sod=SodBinding(
                "S4", "FB60", {"vendor_id": "vendor_id", "company_code": "company_code"}
            ),
        ),
        ToolSpec(
            "s4.payment_run",
            "s4",
            _W,
            "payment",
            "Automatic payment run (F110)",
            sod=SodBinding(
                "S4", "F110", {"vendor_id": "vendor_id", "company_code": "company_code"}
            ),
        ),
        ToolSpec(
            "s4.po_create",
            "s4",
            _W,
            "purchase_order",
            "Create purchase order (ME21N)",
            sod=SodBinding("S4", "ME21N", {"purchase_order": "purchase_order"}),
        ),
        ToolSpec(
            "s4.po_release",
            "s4",
            _W,
            "purchase_order",
            "Release purchase order (ME29N)",
            sod=SodBinding("S4", "ME29N", {"purchase_order": "purchase_order"}),
        ),
        ToolSpec("s4.vendor_get", "s4", _R, "vendor", "Display vendor (XK03)"),
    ]
)
