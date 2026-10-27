# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from agent_governance.crypto import generate_ec_key
from agent_governance.identity.idp import LocalIdentityProvider
from agent_governance.identity.registry import RegistryError, TriggerRegistration
from agent_governance.identity.sts import ExchangeRequest, InvalidTokenError, TokenExchangeError
from agent_governance.model import PrincipalKind
from tests.identity.conftest import ISSUER, TOKEN_URL, Ids


def test_obo_token_has_two_subjects_and_is_sender_constrained(ids: Ids) -> None:
    issued = ids.exchange(
        "access-request", ids.user_token(), scope=["iag.submit_request", "sod.simulate"]
    )
    claims = issued.claims
    assert claims["sub"] == "agent:access-request@1.3.0"
    assert claims["act"] == {"sub": "user:priya@acme"}
    assert claims["aud"] == "iag"
    assert claims["exp"] - claims["iat"] == 300
    assert claims["cnf"]["jkt"] == ids.contract("access-request").key_thumbprint
    assert set(issued.scope) == {"iag.submit_request", "sod.simulate"}
    assert claims["plan_id"] == "plan-1"
    assert claims["session_id"].startswith("sess_")
    verified = ids.sts.verify_access_token(issued.access_token, "iag")
    assert verified.delegation.root == "user:priya@acme"
    assert verified.delegation.root_kind is PrincipalKind.HUMAN


def test_scope_is_contract_and_server_intersection(ids: Ids) -> None:
    issued = ids.exchange(
        "access-request",
        ids.user_token(),
        scope=["iag.submit_request", "iag.grant_assignment", "s4.vendor_create"],
    )
    assert issued.scope == ("iag.submit_request",)
    default = ids.exchange("access-request", ids.user_token())
    assert set(default.scope) == {
        "catalog.search_roles",
        "sod.simulate",
        "iag.draft_request",
        "iag.submit_request",
    }


def test_autonomy_caps_scope(ids: Ids) -> None:
    issued = ids.exchange("certification", ids.user_token())
    assert "review.draft_decision" in issued.scope  # draft allowed
    ids.registry.quarantine("agent:access-request@1.3.0", "test")
    issued = ids.exchange("access-request", ids.user_token())
    assert set(issued.scope) == {"catalog.search_roles", "sod.simulate"}


def test_no_subject_token_means_no_token(ids: Ids) -> None:
    with pytest.raises(TokenExchangeError, match="autonomous delegation is not supported"):
        ids.exchange("access-request", None)
    refused = ids.evidence.records("acme")[-1]
    assert refused.verdict == "refused"
    assert refused.flags == ("invalid_request",)


def test_untrusted_or_wrong_audience_subject_tokens(ids: Ids) -> None:
    rogue = LocalIdentityProvider("https://idp.acme.test", ids.clock)  # same name, different key
    with pytest.raises(TokenExchangeError, match="subject token rejected"):
        ids.exchange("access-request", rogue.issue_user_token("user:priya@acme", ISSUER))
    other = LocalIdentityProvider("https://evil.test", ids.clock)
    with pytest.raises(TokenExchangeError, match="untrusted subject token issuer"):
        ids.exchange("access-request", other.issue_user_token("user:priya@acme", ISSUER))
    with pytest.raises(TokenExchangeError, match="subject token rejected"):
        ids.exchange(
            "access-request", ids.idp.issue_user_token("user:priya@acme", "https://other.test")
        )


def test_subject_must_be_active_human(ids: Ids) -> None:
    with pytest.raises(TokenExchangeError, match="active human"):
        ids.exchange("access-request", ids.idp.issue_user_token("svc:sap-batch-07", ISSUER))
    with pytest.raises(TokenExchangeError, match="active human"):
        ids.exchange("access-request", ids.idp.issue_user_token("user:ghost@acme", ISSUER))


def test_expired_subject_token(ids: Ids) -> None:
    token = ids.idp.issue_user_token("user:priya@acme", ISSUER, lifetime=timedelta(minutes=1))
    ids.clock.advance(timedelta(minutes=2))
    with pytest.raises(TokenExchangeError, match="expired"):
        ids.exchange("access-request", token)


def test_dpop_proof_must_come_from_the_agent_key(ids: Ids) -> None:
    with pytest.raises(TokenExchangeError, match=r"cnf\.jkt"):
        ids.exchange("access-request", ids.user_token(), proof_key=generate_ec_key())


def test_actor_assertion_replay_and_forgery(ids: Ids) -> None:
    from agent_governance.identity.dpop import make_proof
    from agent_governance.identity.idp import make_client_assertion

    contract = ids.contract("access-request")
    assertion = make_client_assertion(
        ids.keys["access-request"], contract.principal_id, TOKEN_URL, ids.clock
    )

    def request(actor: str) -> ExchangeRequest:
        return ExchangeRequest(
            subject_token=ids.user_token(),
            actor_token=actor,
            audience="iag",
            dpop_proof=make_proof(ids.keys["access-request"], "POST", TOKEN_URL, clock=ids.clock),
            token_endpoint=TOKEN_URL,
            plan_id="p",
        )

    ids.sts.exchange(request(assertion))
    with pytest.raises(TokenExchangeError, match="replayed"):
        ids.sts.exchange(request(assertion))
    forged = make_client_assertion(generate_ec_key(), contract.principal_id, TOKEN_URL, ids.clock)
    with pytest.raises(TokenExchangeError, match="agent assertion rejected"):
        ids.sts.exchange(request(forged))


def test_unknown_audience_and_missing_plan(ids: Ids) -> None:
    with pytest.raises(TokenExchangeError, match="unknown tool server"):
        ids.exchange("access-request", ids.user_token(), audience="mainframe")
    with pytest.raises(TokenExchangeError, match="plan_id"):
        ids.exchange("access-request", ids.user_token(), plan_id=None)


def test_retired_agent_cannot_get_tokens(ids: Ids) -> None:
    ids.registry.retire("agent:access-request@1.3.0", datetime(2026, 10, 1, tzinfo=UTC))
    with pytest.raises(TokenExchangeError, match="retired"):
        ids.exchange("access-request", ids.user_token())


def test_handoff_nests_act_and_inherits_plan(ids: Ids) -> None:
    parent = ids.exchange("orchestrator", ids.user_token(), plan_id="plan-9")
    child = ids.exchange(
        "access-request", parent.access_token, plan_id=None, proof_key=ids.keys["orchestrator"]
    )
    assert child.claims["act"] == {
        "sub": "agent:orchestrator@1.3.0",
        "act": {"sub": "user:priya@acme"},
    }
    assert child.claims["plan_id"] == "plan-9"
    assert child.claims["cnf"]["jkt"] == ids.contract("access-request").key_thumbprint
    verified = ids.sts.verify_access_token(child.access_token)
    assert verified.delegation.root == "user:priya@acme"
    assert verified.delegation.depth == 2


def test_handoff_requires_possession_of_parent_token(ids: Ids) -> None:
    parent = ids.exchange("orchestrator", ids.user_token())
    with pytest.raises(TokenExchangeError, match=r"cnf\.jkt"):
        # the receiving agent cannot redeem a token it merely observed
        ids.exchange("access-request", parent.access_token)


def test_handoff_cannot_switch_plans_or_loop(ids: Ids) -> None:
    parent = ids.exchange("orchestrator", ids.user_token(), plan_id="plan-9")
    with pytest.raises(TokenExchangeError, match="delegating plan"):
        ids.exchange(
            "access-request",
            parent.access_token,
            plan_id="plan-x",
            proof_key=ids.keys["orchestrator"],
        )
    with pytest.raises(TokenExchangeError, match="twice"):
        ids.exchange(
            "orchestrator", parent.access_token, plan_id=None, proof_key=ids.keys["orchestrator"]
        )


def test_delegation_depth_is_capped_at_three(ids: Ids) -> None:
    t1 = ids.exchange("orchestrator", ids.user_token())
    t2 = ids.exchange("certification", t1.access_token, proof_key=ids.keys["orchestrator"])
    t3 = ids.exchange("access-request", t2.access_token, proof_key=ids.keys["certification"])
    assert len(ids.sts.verify_access_token(t3.access_token).delegation.chain) == 3
    with pytest.raises(TokenExchangeError, match="depth"):
        ids.exchange(
            "ap-clerk", t3.access_token, audience="s4", proof_key=ids.keys["access-request"]
        )


def test_triggered_token_is_bounded_by_envelope(ids: Ids) -> None:
    now = ids.clock.now()
    ids.registry.register_trigger(
        TriggerRegistration(
            "etd-alerts",
            owner="user:mark@acme",
            envelope=frozenset({"catalog.search_roles"}),
            approved_by="user:mark@acme",
            approved_at=now,
        )
    )
    token = ids.bus.issue_trigger_token("etd-alerts", "8812", ISSUER)
    issued = ids.exchange("access-request", token)
    assert issued.scope == ("catalog.search_roles",)
    assert issued.claims["act"] == {"sub": "trigger:etd-alerts"}
    assert (
        ids.sts.verify_access_token(issued.access_token).delegation.root_kind
        is PrincipalKind.TRIGGER
    )
    with pytest.raises(TokenExchangeError, match="no requested tool"):
        ids.exchange(
            "access-request",
            ids.bus.issue_trigger_token("etd-alerts", "8813", ISSUER),
            scope=["iag.submit_request"],
        )
    ids.registry.disable_trigger("etd-alerts")
    with pytest.raises(TokenExchangeError, match="disabled"):
        ids.exchange("access-request", ids.bus.issue_trigger_token("etd-alerts", "8814", ISSUER))


def test_unregistered_trigger_and_owner_rules(ids: Ids) -> None:
    with pytest.raises(TokenExchangeError, match="unregistered trigger"):
        ids.exchange("access-request", ids.bus.issue_trigger_token("nope", "1", ISSUER))
    with pytest.raises(RegistryError, match="owner must approve"):
        ids.registry.register_trigger(
            TriggerRegistration(
                "t",
                owner="user:mark@acme",
                envelope=frozenset({"x"}),
                approved_by="user:priya@acme",
                approved_at=ids.clock.now(),
            )
        )


def test_access_token_verification_failures(ids: Ids) -> None:
    issued = ids.exchange("access-request", ids.user_token())
    with pytest.raises(InvalidTokenError):
        ids.sts.verify_access_token(issued.access_token, "s4")  # wrong audience
    ids.clock.advance(timedelta(minutes=6))
    with pytest.raises(InvalidTokenError, match="expired"):
        ids.sts.verify_access_token(issued.access_token)
    forged_claims = {**issued.claims, "scope": "iag.grant_assignment"}
    forged = jwt.encode(forged_claims, generate_ec_key(), algorithm="ES256")
    with pytest.raises(InvalidTokenError):
        ids.sts.verify_access_token(forged)


def test_revocation_by_jti_and_subject(ids: Ids) -> None:
    a = ids.exchange("access-request", ids.user_token())
    ids.revocations.revoke_token(a.claims["jti"], a.claims["exp"])
    with pytest.raises(InvalidTokenError, match="revoked"):
        ids.sts.verify_access_token(a.access_token)
    b = ids.exchange("access-request", ids.user_token())
    ids.revocations.revoke_subject("agent:access-request@1.3.0", ids.clock.now())
    with pytest.raises(InvalidTokenError, match="revoked"):
        ids.sts.verify_access_token(b.access_token)
    ids.clock.advance(timedelta(seconds=1))
    c = ids.exchange("access-request", ids.user_token())
    ids.sts.verify_access_token(c.access_token)  # tokens issued after the cutoff are fine


def test_issuance_is_evidenced(ids: Ids) -> None:
    issued = ids.exchange("access-request", ids.user_token())
    record = ids.evidence.records("acme", kinds=["token.exchange"])[-1]
    assert record.verdict == "issued"
    assert record.details["jti"] == issued.claims["jti"]
    assert record.actor == {"agent": "agent:access-request@1.3.0", "delegator": "user:priya@acme"}


def test_jwks_exposes_public_key_only(ids: Ids) -> None:
    [key] = ids.sts.jwks()["keys"]
    assert "d" not in key
    assert key["alg"] == "ES256"
