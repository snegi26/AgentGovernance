# SPDX-License-Identifier: Apache-2.0
"""Composition root: wires identity, policy, SoD, approvals, evidence and the gateway together."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_governance.approval.service import ApprovalService, ApproverDirectory
from agent_governance.core import Clock, SystemClock
from agent_governance.crypto import generate_ec_key, generate_ed25519_key
from agent_governance.evidence.anchor import LocalTimestampAuthority, TimestampAuthority
from agent_governance.evidence.packet import PacketBuilder
from agent_governance.evidence.record import EvidenceKind
from agent_governance.evidence.store import EvidenceStore
from agent_governance.gateway.backends import CallContext, InMemoryBackend, ToolBackend
from agent_governance.gateway.gateway import Gateway
from agent_governance.identity.dpop import DpopVerifier
from agent_governance.identity.idp import TrustedIssuer
from agent_governance.identity.registry import AgentContract, AgentRegistry, UnknownAgentError
from agent_governance.identity.revocation import RevocationList
from agent_governance.identity.sts import TokenService
from agent_governance.model import Inventory
from agent_governance.policy.engine import PolicyEngine
from agent_governance.policy.tools import DEFAULT_TOOLS, ToolCatalog
from agent_governance.sod.engine import SodEngine
from agent_governance.sod.ruleset import Ruleset
from agent_governance.sod.session import SessionChecker, SqliteSessionStore


@dataclass(frozen=True)
class Settings:
    tenant: str = "acme"
    base_url: str = "https://gov.acme.test"
    evidence_path: str = ":memory:"
    session_path: str = ":memory:"
    ruleset_path: str | None = None
    policy_path: str | None = None

    @property
    def issuer(self) -> str:
        return self.base_url

    @property
    def token_endpoint(self) -> str:
        return f"{self.base_url}/token"

    def mcp_url(self, server: str) -> str:
        return f"{self.base_url}/mcp/{server}"


@dataclass
class Keys:
    """Service keys. Production loads these from a KMS/HSM; the defaults are ephemeral."""

    token_signing: ec.EllipticCurvePrivateKey = field(default_factory=generate_ec_key)
    approval_signing: Ed25519PrivateKey = field(default_factory=generate_ed25519_key)
    packet_signing: Ed25519PrivateKey = field(default_factory=generate_ed25519_key)
    tsa: Ed25519PrivateKey = field(default_factory=generate_ed25519_key)


class Runtime:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        clock: Clock | None = None,
        inventory: Inventory | None = None,
        ruleset: Ruleset | None = None,
        tools: ToolCatalog = DEFAULT_TOOLS,
        trusted_issuers: Iterable[TrustedIssuer] = (),
        keys: Keys | None = None,
        backend: ToolBackend | None = None,
        tsa: TimestampAuthority | None = None,
        approver_grants: Mapping[Any, Iterable[str]] | None = None,
    ) -> None:
        self.settings = settings or Settings()
        self.clock = clock or SystemClock()
        self.keys = keys or Keys()
        self.inventory = inventory or Inventory()
        self.tools = tools
        if ruleset is None:
            ruleset = (
                Ruleset.load(self.settings.ruleset_path)
                if self.settings.ruleset_path
                else Ruleset.starter()
            )
        self.ruleset = ruleset
        tenant = self.settings.tenant

        self.evidence = EvidenceStore(self.settings.evidence_path, self.clock)
        self.registry = AgentRegistry(self.inventory, listener=self._on_registry_change)
        self.revocations = RevocationList()
        self.dpop = DpopVerifier(self.clock)
        self.tokens = TokenService(
            issuer=self.settings.issuer,
            tenant=tenant,
            signing_key=self.keys.token_signing,
            registry=self.registry,
            inventory=self.inventory,
            tools=tools,
            trusted_issuers=trusted_issuers,
            revocations=self.revocations,
            dpop=self.dpop,
            evidence=self.evidence,
            clock=self.clock,
        )
        self.directory = ApproverDirectory(self.inventory, approver_grants, self._trigger_owner)
        self.approvals = ApprovalService(
            tenant=tenant,
            signing_key=self.keys.approval_signing,
            directory=self.directory,
            evidence=self.evidence,
            clock=self.clock,
        )
        self.policy = (
            PolicyEngine.from_file(self.settings.policy_path)
            if self.settings.policy_path
            else PolicyEngine.default()
        )
        self.sod = SodEngine(ruleset, self.inventory, self.clock)
        self.session = SessionChecker(
            ruleset, SqliteSessionStore(self.settings.session_path), self.inventory, self.clock
        )
        self.tsa = tsa or LocalTimestampAuthority(
            self.keys.tsa, name=f"{tenant}-local-tsa", clock=self.clock
        )
        if backend is None:
            memory = InMemoryBackend(self.inventory)
            memory.register("gateway.quarantine", self._quarantine_tool)
            backend = memory
        self.backend = backend
        self.gateway = Gateway(
            tenant=tenant,
            tokens=self.tokens,
            dpop=self.dpop,
            registry=self.registry,
            inventory=self.inventory,
            tools=tools,
            policy=self.policy,
            sod=self.sod,
            session=self.session,
            approvals=self.approvals,
            evidence=self.evidence,
            backend=backend,
            clock=self.clock,
        )

    def close(self) -> None:
        """Release database handles."""
        self.evidence.close()
        self.session.store.close()

    def __enter__(self) -> Runtime:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- operations -------------------------------------------------------------------------

    def quarantine(self, agent_principal: str, reason: str) -> AgentContract:
        """Drop an agent to read-only and revoke every token it holds."""
        contract = self.registry.quarantine(agent_principal, reason)
        self.revocations.revoke_subject(agent_principal, self.clock.now())
        return contract

    def anchor(self, day: date | str) -> None:
        self.evidence.anchor_day(self.settings.tenant, day, self.tsa)

    def packet(self, control_id: str, start: date, end: date) -> dict[str, Any]:
        builder = PacketBuilder(self.evidence, self.keys.packet_signing, self.clock)
        return builder.build(self.settings.tenant, control_id, start, end)

    def _quarantine_tool(self, args: Mapping[str, Any], ctx: CallContext) -> dict[str, Any]:
        contract = self.quarantine(str(args["agent"]), str(args.get("reason", "anomaly monitor")))
        return {
            "status": "quarantined",
            "agent": contract.principal_id,
            "decision_id": ctx.decision_id,
        }

    def _trigger_owner(self, trigger_principal: str) -> str | None:
        try:
            return self.registry.trigger(trigger_principal.removeprefix("trigger:")).owner
        except UnknownAgentError:
            return None

    def _on_registry_change(self, event: str, payload: dict[str, Any]) -> None:
        self.evidence.append(
            self.settings.tenant,
            EvidenceKind.REGISTRY_CHANGE,
            actor={"agent": payload.get("principal_id"), "delegator": payload.get("approved_by")},
            verdict=event,
            details=payload,
        )
