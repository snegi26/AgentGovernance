# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from agent_governance.core import FixedClock
from agent_governance.crypto import ec_public_jwk, generate_ec_key
from agent_governance.evidence.store import EvidenceStore
from agent_governance.identity.dpop import DpopVerifier, make_proof
from agent_governance.identity.idp import (
    LocalEventBus,
    LocalIdentityProvider,
    make_client_assertion,
)
from agent_governance.identity.registry import AgentContract, AgentRegistry, Autonomy, EvalStatus
from agent_governance.identity.revocation import RevocationList
from agent_governance.identity.sts import ExchangeRequest, IssuedToken, TokenService
from agent_governance.model import Inventory
from agent_governance.policy.tools import DEFAULT_TOOLS

TOKEN_URL = "https://gov.acme.test/token"
ISSUER = "https://gov.acme.test"


@dataclass
class Ids:
    clock: FixedClock
    sts: TokenService
    registry: AgentRegistry
    idp: LocalIdentityProvider
    bus: LocalEventBus
    evidence: EvidenceStore
    revocations: RevocationList
    keys: dict[str, ec.EllipticCurvePrivateKey]

    def contract(self, name: str) -> AgentContract:
        return next(a for a in self.registry.agents() if a.agent_id == name)

    def exchange(
        self,
        agent: str,
        subject_token: str | None,
        audience: str = "iag",
        *,
        scope: list[str] | None = None,
        plan_id: str | None = "plan-1",
        proof_key: ec.EllipticCurvePrivateKey | None = None,
        **kw: Any,
    ) -> IssuedToken:
        contract = self.contract(agent)
        key = self.keys[agent]
        return self.sts.exchange(
            ExchangeRequest(
                subject_token=subject_token,
                actor_token=make_client_assertion(
                    key, contract.principal_id, TOKEN_URL, self.clock
                ),
                audience=audience,
                dpop_proof=make_proof(proof_key or key, "POST", TOKEN_URL, clock=self.clock),
                token_endpoint=TOKEN_URL,
                scope=scope,
                plan_id=plan_id,
                **kw,
            )
        )

    def user_token(self, user: str = "user:priya@acme") -> str:
        return self.idp.issue_user_token(user, ISSUER)


def build_ids(clock: FixedClock, inventory: Inventory) -> Ids:
    evidence = EvidenceStore(clock=clock)
    registry = AgentRegistry(inventory)
    keys: dict[str, ec.EllipticCurvePrivateKey] = {}

    handoffs = {
        "orchestrator": frozenset({"access-request", "certification"}),
        "certification": frozenset({"access-request"}),
        "access-request": frozenset({"ap-clerk"}),
    }

    def register(name: str, tools: set[str], autonomy: Autonomy) -> None:
        keys[name] = generate_ec_key()
        registry.register(
            AgentContract(
                agent_id=name,
                version="1.3.0",
                owner="user:mark@acme",
                model_ref="provider/model@2026-10-01",
                allowed_tools=frozenset(tools),
                max_autonomy=autonomy,
                public_jwk=ec_public_jwk(keys[name]),
                eval_status=EvalStatus.PASSED,
                may_delegate_to=handoffs.get(name, frozenset()),
            )
        )

    register(
        "access-request",
        {"catalog.search_roles", "sod.simulate", "iag.draft_request", "iag.submit_request"},
        Autonomy.WRITE_WITH_APPROVAL,
    )
    register("orchestrator", {"catalog.search_roles", "review.list_items"}, Autonomy.READ)
    register(
        "certification",
        {"review.list_items", "usage.get", "sod.static", "review.draft_decision"},
        Autonomy.DRAFT,
    )
    register(
        "ap-clerk",
        {"s4.vendor_create", "s4.invoice_post", "s4.vendor_get"},
        Autonomy.WRITE_WITH_APPROVAL,
    )
    idp = LocalIdentityProvider("https://idp.acme.test", clock)
    bus = LocalEventBus("https://events.acme.test", clock)
    revocations = RevocationList()
    sts = TokenService(
        issuer=ISSUER,
        tenant="acme",
        signing_key=generate_ec_key(),
        registry=registry,
        inventory=inventory,
        tools=DEFAULT_TOOLS,
        trusted_issuers=[idp.trusted, bus.trusted],
        revocations=revocations,
        dpop=DpopVerifier(clock),
        evidence=evidence,
        clock=clock,
    )
    return Ids(clock, sts, registry, idp, bus, evidence, revocations, keys)


@pytest.fixture
def ids(clock: FixedClock, inventory: Inventory) -> Ids:
    return build_ids(clock, inventory)
