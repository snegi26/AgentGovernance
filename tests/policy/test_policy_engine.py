# SPDX-License-Identifier: Apache-2.0
"""Each default Cedar policy pinned by a case that only it decides."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from agent_governance.crypto import ec_public_jwk, generate_ec_key
from agent_governance.identity.registry import AgentContract, Autonomy
from agent_governance.policy.engine import (
    DelegatorContext,
    PolicyEngine,
    PolicyEngineError,
    PolicyInput,
    PolicyVerdict,
)
from agent_governance.policy.tools import DEFAULT_TOOLS

ENGINE = PolicyEngine.default()
AGENT = AgentContract(
    agent_id="a",
    version="1",
    owner="user:o",
    model_ref="m",
    allowed_tools=frozenset(
        {"iag.submit_request", "catalog.search_roles", "iag.draft_request", "iag.grant_assignment"}
    ),
    max_autonomy=Autonomy.WRITE_WITH_APPROVAL,
    public_jwk=ec_public_jwk(generate_ec_key()),
)
HUMAN = DelegatorContext(
    "human",
    "user:p",
    frozenset(
        {
            "request_access_self_or_reports",
            "governance.use_assistant",
            "catalog.search_roles",
            "iag.draft_request",
            "provision_access",
        }
    ),
)


def _input(tool: str = "iag.submit_request", **kw: Any) -> PolicyInput:
    base: dict[str, Any] = {
        "agent": AGENT,
        "tool": DEFAULT_TOOLS.get(tool),
        "delegator": HUMAN,
        "token_scope": AGENT.allowed_tools,
        "call_hash": "sha256:call",
        "approval_valid": False,
        "approval_hash": "",
        "approval_required": False,
        "sod_verdict": "allow",
    }
    return PolicyInput(**{**base, **kw})


def _decide(**kw: Any) -> tuple[PolicyVerdict, tuple[str, ...]]:
    decision = ENGINE.evaluate(_input(**kw))
    return decision.verdict, decision.determining_policies


def test_permits_write_within_contract_and_entitlement() -> None:
    assert _decide() == (PolicyVerdict.ALLOW, ("write.within-contract",))


def test_read_permit() -> None:
    assert _decide(tool="catalog.search_roles")[0] is PolicyVerdict.ALLOW


@pytest.mark.parametrize(
    "change",
    [
        {"delegator": replace(HUMAN, entitlements=frozenset())},
        {"delegator": replace(HUMAN, kind="agent")},
        {"token_scope": frozenset()},
        {"agent": replace(AGENT, allowed_tools=frozenset({"catalog.search_roles"}))},
    ],
)
def test_no_permit_means_deny(change: dict[str, Any]) -> None:
    verdict, policies = _decide(**change)
    assert verdict is PolicyVerdict.DENY
    assert policies == ()


@pytest.mark.parametrize(
    ("change", "policy"),
    [
        (
            {"agent": replace(AGENT, max_autonomy=Autonomy.DRAFT)},
            "autonomy.writes-need-write-autonomy",
        ),
        ({"agent": replace(AGENT, quarantined=True)}, "quarantine.no-writes"),
        ({"sod_verdict": "deny"}, "sod.deny-is-final"),
    ],
)
def test_forbids_override_permit_even_with_approval(change: dict[str, Any], policy: str) -> None:
    verdict, policies = _decide(
        approval_valid=True, approval_hash="sha256:call", approval_required=True, **change
    )
    assert verdict is PolicyVerdict.DENY
    assert policy in policies


def test_read_only_agent_cannot_draft() -> None:
    verdict, policies = _decide(
        tool="iag.draft_request", agent=replace(AGENT, max_autonomy=Autonomy.READ)
    )
    assert verdict is PolicyVerdict.DENY
    assert policies == ("autonomy.read-only-agents-cannot-draft",)


def test_required_approval_turns_into_require_approval() -> None:
    assert _decide(approval_required=True)[0] is PolicyVerdict.REQUIRE_APPROVAL
    assert (
        _decide(approval_required=True, approval_valid=True, approval_hash="sha256:call")[0]
        is PolicyVerdict.ALLOW
    )


def test_approval_for_other_payload_does_not_count() -> None:
    verdict, policies = _decide(
        approval_required=True, approval_valid=True, approval_hash="sha256:other"
    )
    assert verdict is PolicyVerdict.DENY
    assert "approval.required-and-bound-to-payload" in policies


def test_grants_need_approval_even_when_tier_says_none() -> None:
    assert _decide(tool="iag.grant_assignment")[0] is PolicyVerdict.REQUIRE_APPROVAL


def test_injection_flag_requires_approval() -> None:
    assert _decide(flags=["possible_injection"])[0] is PolicyVerdict.REQUIRE_APPROVAL


def test_invalid_policy_text_is_rejected() -> None:
    with pytest.raises(PolicyEngineError, match="invalid Cedar"):
        PolicyEngine("permit (principal, action, resource) when {")


def test_custom_policy_file(tmp_path: Any) -> None:
    path = tmp_path / "deny-all.cedar"
    path.write_text('@id("deny-all")\nforbid (principal, action, resource);')
    engine = PolicyEngine.from_file(path)
    assert engine.evaluate(_input()).verdict is PolicyVerdict.DENY
