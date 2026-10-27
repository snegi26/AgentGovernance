# SPDX-License-Identifier: Apache-2.0
"""A synthetic but fully wired estate: fixtures loaded through the real connectors, agents
registered with their own keys, approvers, an IdP and an event bus."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from agent_governance.approval.tiers import ApproverRole
from agent_governance.connectors.base import load_into
from agent_governance.connectors.entra import EntraConnector
from agent_governance.connectors.sap import SapS4Connector
from agent_governance.core import Clock, FixedClock
from agent_governance.crypto import ec_public_jwk, generate_ec_key
from agent_governance.gateway.client import AgentClient
from agent_governance.identity.idp import LocalEventBus, LocalIdentityProvider
from agent_governance.identity.registry import (
    AgentContract,
    Autonomy,
    EvalStatus,
    TriggerRegistration,
)
from agent_governance.model import Inventory
from agent_governance.runtime import Runtime, Settings

DEMO_START = datetime(2026, 10, 27, 14, 0, tzinfo=UTC)
MODEL_REF = "provider/model@2026-10-01"

#: (agent_id, version, allowed tools, max autonomy, owner)
AGENTS: tuple[tuple[str, str, frozenset[str], Autonomy, str], ...] = (
    (
        "orchestrator",
        "1.0.0",
        frozenset({"catalog.search_roles", "review.list_items"}),
        Autonomy.READ,
        "user:mark@acme",
    ),
    (
        "access-request",
        "1.3.0",
        frozenset(
            {"catalog.search_roles", "sod.simulate", "iag.draft_request", "iag.submit_request"}
        ),
        Autonomy.WRITE_WITH_APPROVAL,
        "user:mark@acme",
    ),
    (
        "ap-automation",
        "1.0.0",
        frozenset({"s4.vendor_create", "s4.invoice_post", "s4.vendor_get", "s4.payment_run"}),
        Autonomy.WRITE_WITH_APPROVAL,
        "user:mark@acme",
    ),
    (
        "provisioner",
        "1.0.0",
        frozenset({"iag.grant_assignment"}),
        Autonomy.WRITE_WITH_APPROVAL,
        "user:ines@acme",
    ),
    (
        "certification",
        "1.0.0",
        frozenset({"review.list_items", "usage.get", "sod.static", "review.draft_decision"}),
        Autonomy.DRAFT,
        "user:mark@acme",
    ),
    (
        "cert-executor",
        "1.0.0",
        frozenset({"review.revoke"}),
        Autonomy.WRITE_WITH_APPROVAL,
        "user:mark@acme",
    ),
    (
        "anomaly-monitor",
        "1.0.0",
        frozenset({"trace.query", "baseline.get", "case.draft", "gateway.quarantine"}),
        Autonomy.WRITE,
        "user:raj@acme",
    ),
)


@dataclass
class DemoEstate:
    runtime: Runtime
    idp: LocalIdentityProvider
    bus: LocalEventBus
    agents: dict[str, AgentClient] = field(default_factory=dict)

    @property
    def clock(self) -> Clock:
        return self.runtime.clock

    def agent(self, agent_id: str) -> AgentClient:
        return self.agents[agent_id]

    def user_token(self, user: str) -> str:
        return self.idp.issue_user_token(user, self.runtime.settings.issuer)

    def trigger_token(self, trigger_id: str, event_id: str) -> str:
        return self.bus.issue_trigger_token(trigger_id, event_id, self.runtime.settings.issuer)


def _fixture(name: str) -> str:
    return resources.files("agent_governance.fixtures").joinpath(name).read_text(encoding="utf-8")


def build_demo(
    clock: Clock | None = None, settings: Settings | None = None, **runtime_kw: Any
) -> DemoEstate:
    clock = clock or FixedClock(DEMO_START)
    idp = LocalIdentityProvider("https://idp.acme.test", clock)
    bus = LocalEventBus("https://events.acme.test", clock)
    inventory = Inventory()
    load_into(
        inventory,
        EntraConnector(json.loads(_fixture("entra.json"))),
        SapS4Connector(json.loads(_fixture("sap_s4.json"))),
    )
    runtime = Runtime(
        settings,
        clock=clock,
        inventory=inventory,
        trusted_issuers=[idp.trusted, bus.trusted],
        approver_grants={
            ApproverRole.ROLE_OWNER: ["user:mark@acme"],
            ApproverRole.CONTROL_OWNER: ["user:cora@acme"],
            ApproverRole.REVIEWER: ["user:mark@acme"],
            ApproverRole.SECURITY_ADMIN: ["user:ines@acme"],
        },
        **runtime_kw,
    )
    estate = DemoEstate(runtime, idp, bus)
    for agent_id, version, tools, autonomy, owner in AGENTS:
        key: ec.EllipticCurvePrivateKey = generate_ec_key()
        contract = runtime.registry.register(
            AgentContract(
                agent_id=agent_id,
                version=version,
                owner=owner,
                model_ref=MODEL_REF,
                allowed_tools=tools,
                max_autonomy=autonomy,
                public_jwk=ec_public_jwk(key),
                eval_status=EvalStatus.SHADOW,
            )
        )
        estate.agents[agent_id] = AgentClient(runtime, contract.principal_id, key)
    runtime.registry.register_trigger(
        TriggerRegistration(
            trigger_id="etd-alerts",
            owner="user:raj@acme",
            envelope=frozenset({"trace.query", "baseline.get", "case.draft", "gateway.quarantine"}),
            entitlements=frozenset({"quarantine_agents"}),
            approved_by="user:raj@acme",
            approved_at=clock.now(),
            description="Enterprise threat detection alert batches",
        )
    )
    return estate
