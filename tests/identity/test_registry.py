# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Any

import pytest

from agent_governance.crypto import ec_public_jwk, generate_ec_key
from agent_governance.identity.registry import (
    AgentContract,
    AgentRegistry,
    Autonomy,
    RegistryError,
    UnknownAgentError,
)
from agent_governance.model import Inventory, Principal, PrincipalKind


def _contract(**kw: Any) -> AgentContract:
    base: dict[str, Any] = {
        "agent_id": "access-request",
        "version": "1.3.0",
        "owner": "user:mark@acme",
        "model_ref": "m@1",
        "allowed_tools": frozenset({"iag.submit_request"}),
        "max_autonomy": Autonomy.WRITE_WITH_APPROVAL,
        "public_jwk": ec_public_jwk(generate_ec_key()),
    }
    return AgentContract(**{**base, **kw})


def test_register_and_lookup(inventory: Inventory) -> None:
    events: list[str] = []
    registry = AgentRegistry(inventory, listener=lambda e, _: events.append(e))
    contract = registry.register(_contract())
    assert registry.get("agent:access-request@1.3.0") == contract
    assert events == ["agent.registered"]
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(_contract())
    with pytest.raises(UnknownAgentError):
        registry.get("agent:nope@1")


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"owner": "svc:sap-batch-07"}, "human"),
        ({"owner": "user:ghost@acme"}, "human"),
        ({"allowed_tools": frozenset()}, "at least one tool"),
        ({"public_jwk": {"kty": "EC", "d": "x"}}, "public key only"),
    ],
)
def test_invalid_contracts(inventory: Inventory, kw: dict[str, Any], message: str) -> None:
    with pytest.raises(RegistryError, match=message):
        AgentRegistry(inventory).register(_contract(**kw))


def test_quarantine_and_owner_restore(inventory: Inventory) -> None:
    registry = AgentRegistry(inventory)
    registry.register(_contract())
    q = registry.quarantine("agent:access-request@1.3.0", "deny-rate spike")
    assert q.max_autonomy is Autonomy.READ
    assert q.quarantined
    assert registry.quarantine("agent:access-request@1.3.0", "again") == q  # idempotent
    with pytest.raises(RegistryError, match="owner"):
        registry.restore("agent:access-request@1.3.0", approved_by="user:priya@acme")
    restored = registry.restore("agent:access-request@1.3.0", approved_by="user:mark@acme")
    assert restored.max_autonomy is Autonomy.WRITE_WITH_APPROVAL
    assert not restored.quarantined
    with pytest.raises(RegistryError, match="not quarantined"):
        registry.restore("agent:access-request@1.3.0", approved_by="user:mark@acme")


def test_nhi_and_trigger_principals_need_owner() -> None:
    with pytest.raises(ValueError, match="human owner"):
        Principal("svc:x", PrincipalKind.NHI)
    with pytest.raises(ValueError, match="human owner"):
        Principal("trigger:x", PrincipalKind.TRIGGER)
