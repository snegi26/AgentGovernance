# SPDX-License-Identifier: Apache-2.0
"""The HTTP agent client against the real HTTP surface, holding only the agent's key."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from agent_governance.agents.client import (
    GatewayClientError,
    RemoteAgentClient,
    RemoteToken,
    RpcError,
    TokenExchangeFailedError,
)
from agent_governance.approval.tiers import ApproverRole
from agent_governance.crypto import generate_ec_key
from agent_governance.demo.estate import DemoEstate, build_demo
from agent_governance.gateway.http import create_app

BASE = "https://gov.acme.test"
PRIYA = "user:priya@acme"
MARK = "user:mark@acme"


@pytest.fixture
def estate() -> Iterator[DemoEstate]:
    estate = build_demo()
    yield estate
    estate.runtime.close()


@pytest.fixture
def http(estate: DemoEstate) -> TestClient:
    return TestClient(create_app(estate.runtime), base_url=BASE)


@pytest.fixture
def remote(estate: DemoEstate, http: TestClient) -> Callable[[str], RemoteAgentClient]:
    """A remote client for a demo agent, built from its public URL and its own key only."""

    def build(agent_id: str) -> RemoteAgentClient:
        agent = estate.agent(agent_id)
        return RemoteAgentClient(BASE, agent.principal_id, agent.key, http, clock=estate.clock)

    return build


def test_exchange_and_read(estate: DemoEstate, remote: Callable[[str], RemoteAgentClient]) -> None:
    client = remote("access-request")
    token = client.exchange(estate.user_token(PRIYA), "iag", plan_id="plan-remote")

    assert token.audience == "iag"
    assert "iag.submit_request" in token.scope
    assert 0 < token.expires_in <= 300
    result = client.call(token, "catalog.search_roles", {"query": "vendor"})
    assert result.allowed
    assert result.result is not None
    assert result.evidence_id is not None


def test_list_tools_shows_only_the_token_scope(
    estate: DemoEstate, remote: Callable[[str], RemoteAgentClient]
) -> None:
    client = remote("access-request")
    token = client.exchange(
        estate.user_token(PRIYA), "iag", plan_id="p", scope=["catalog.search_roles"]
    )
    assert [t["name"] for t in client.list_tools(token)] == ["catalog.search_roles"]


def test_write_parks_for_approval_then_runs_with_it(
    estate: DemoEstate, remote: Callable[[str], RemoteAgentClient]
) -> None:
    client = remote("ap-automation")
    token = client.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    vendor = {"vendor_id": "V-1", "name": "Northwind"}

    parked = client.call(token, "s4.vendor_create", vendor)
    assert parked.verdict == "require_approval"
    assert parked.result is None
    assert parked.approval_task_id is not None
    # The approver acts through their own channel; the agent only carries the signed token.
    approval = estate.runtime.approvals.approve(
        parked.approval_task_id, MARK, ApproverRole.LINE_MANAGER
    )

    done = client.call(token, "s4.vendor_create", vendor, approvals=[approval])
    assert done.allowed
    assert done.result is not None
    denied = client.call(token, "s4.invoice_post", {"vendor_id": "V-1", "company_code": "1000"})
    assert denied.verdict == "deny"
    assert "P2P-01" in denied.reason
    assert denied.sod_result_ref is not None


def test_shadow_decision_is_visible_to_the_agent(
    estate: DemoEstate, remote: Callable[[str], RemoteAgentClient]
) -> None:
    client = remote("ap-automation@1.1.0")
    token = client.exchange(estate.user_token(PRIYA), "s4", plan_id="p")

    result = client.call(token, "s4.vendor_create", {"vendor_id": "V-1"})

    assert result.verdict == "require_approval"
    assert result.shadow
    assert result.approval_task_id is None
    assert "shadow" in result.flags


def test_token_is_useless_with_another_key(
    estate: DemoEstate, http: TestClient, remote: Callable[[str], RemoteAgentClient]
) -> None:
    token = remote("access-request").exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    agent = estate.agent("access-request")
    thief = RemoteAgentClient(BASE, agent.principal_id, generate_ec_key(), http, clock=estate.clock)

    result = thief.call(token, "catalog.search_roles", {"query": "vendor"})

    assert result.verdict == "deny"
    assert "DPoP" in result.reason


def test_exchange_failures_raise(
    estate: DemoEstate, http: TestClient, remote: Callable[[str], RemoteAgentClient]
) -> None:
    with pytest.raises(TokenExchangeFailedError) as unknown_server:
        remote("access-request").exchange(estate.user_token(PRIYA), "nowhere", plan_id="p")
    assert unknown_server.value.error == "invalid_target"

    agent = estate.agent("access-request")
    impostor = RemoteAgentClient(
        BASE, agent.principal_id, generate_ec_key(), http, clock=estate.clock
    )
    with pytest.raises(TokenExchangeFailedError) as bad_client:
        impostor.exchange(estate.user_token(PRIYA), "iag", plan_id="p")
    assert bad_client.value.error == "invalid_client"


def test_tool_on_another_server_is_an_rpc_error(
    estate: DemoEstate, remote: Callable[[str], RemoteAgentClient]
) -> None:
    client = remote("ap-automation")
    token = client.exchange(estate.user_token(PRIYA), "s4", plan_id="p")
    with pytest.raises(RpcError) as error:
        client.call(token, "catalog.search_roles", {})
    assert error.value.code == -32602


TOKEN = RemoteToken("t", "iag", ("catalog.search_roles",), 300)


def _scripted(handler: Callable[[httpx.Request], httpx.Response]) -> RemoteAgentClient:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return RemoteAgentClient(BASE + "/", "agent:a@1", generate_ec_key(), http)


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, text="<html>"), "non-JSON"),
        (httpx.Response(200, json=[1]), "not an object"),
        (httpx.Response(502, json={}), "HTTP 502"),
        (httpx.Response(200, json={"jsonrpc": "2.0", "id": 99, "result": {}}), "id does not"),
        (httpx.Response(200, json={"jsonrpc": "2.0", "id": 0}), "no result"),
        (
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 0, "result": {"content": []}}),
            "no governance decision",
        ),
    ],
)
def test_malformed_gateway_answers_are_errors(response: httpx.Response, message: str) -> None:
    client = _scripted(lambda _: response)
    with pytest.raises(GatewayClientError, match=message):
        client.call(TOKEN, "catalog.search_roles")


def test_requests_target_the_configured_public_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body: dict[str, Any] = {"access_token": "t", "token_type": "Bearer", "expires_in": 300}
        return httpx.Response(200, json=body)

    client = _scripted(handler)
    with pytest.raises(GatewayClientError, match="not DPoP-bound"):
        client.exchange("subject", "iag", plan_id="p")
    assert str(seen[0].url) == f"{BASE}/token"
    assert seen[0].headers["DPoP"]


def test_client_module_loads_no_service_internals() -> None:
    """Importing the client must not pull in anything that holds or uses a service key."""
    probe = (
        "import sys, agent_governance.agents.client\n"
        "bad = ('runtime', 'gateway', 'approval', 'evidence', 'identity.sts', "
        "'identity.registry', 'sod', 'policy')\n"
        "print(sorted(m for m in sys.modules if m.startswith('agent_governance.') "
        "and m.removeprefix('agent_governance.').startswith(bad)))\n"
    )
    loaded = subprocess.run(  # noqa: S603 - fixed interpreter and script
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert loaded == "[]"
