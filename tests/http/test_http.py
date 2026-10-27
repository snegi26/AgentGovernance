# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent_governance.demo.estate import DemoEstate, build_demo
from agent_governance.gateway.http import create_app
from agent_governance.identity.dpop import make_proof
from agent_governance.identity.idp import make_client_assertion
from agent_governance.identity.sts import TOKEN_EXCHANGE_GRANT, TOKEN_TYPE_JWT

BASE = "https://gov.acme.test"
PRIYA = "user:priya@acme"


@pytest.fixture
def estate() -> Iterator[DemoEstate]:
    estate = build_demo()
    yield estate
    estate.runtime.close()


@pytest.fixture
def client(estate: DemoEstate) -> TestClient:
    return TestClient(create_app(estate.runtime), base_url=BASE)


def _token(
    client: TestClient, estate: DemoEstate, agent_id: str, audience: str, user: str = PRIYA
) -> str:
    agent = estate.agent(agent_id)
    response = client.post(
        "/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": estate.user_token(user),
            "subject_token_type": TOKEN_TYPE_JWT,
            "actor_token": make_client_assertion(
                agent.key, agent.principal_id, f"{BASE}/token", estate.clock
            ),
            "actor_token_type": TOKEN_TYPE_JWT,
            "audience": audience,
            "plan_id": "plan-http",
        },
        headers={"DPoP": make_proof(agent.key, "POST", f"{BASE}/token", clock=estate.clock)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "DPoP"
    assert response.headers["cache-control"] == "no-store"
    return str(body["access_token"])


def _rpc(  # noqa: PLR0917 - mirrors the JSON-RPC envelope fields
    client: TestClient,
    estate: DemoEstate,
    agent_id: str,
    server: str,
    token: str,
    method: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    agent = estate.agent(agent_id)
    proof = make_proof(
        agent.key, "POST", f"{BASE}/mcp/{server}", clock=estate.clock, access_token=token
    )
    response = client.post(
        f"/mcp/{server}",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers={"Authorization": f"DPoP {token}", "DPoP": proof},
    )
    assert response.status_code == 200
    return dict(response.json())


def test_health_and_jwks(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/.well-known/jwks.json").json()["keys"][0]["alg"] == "ES256"


def test_token_errors_follow_oauth(client: TestClient, estate: DemoEstate) -> None:
    response = client.post("/token", data={"grant_type": "password"})
    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_grant_type"
    response = client.post("/token", json={})
    assert response.json()["error"] == "invalid_request"


def test_tools_list_shows_only_scoped_tools(client: TestClient, estate: DemoEstate) -> None:
    token = _token(client, estate, "access-request", "iag")
    body = _rpc(client, estate, "access-request", "iag", token, "tools/list", {})
    names = {t["name"] for t in body["result"]["tools"]}
    assert names == {
        "catalog.search_roles",
        "sod.simulate",
        "iag.draft_request",
        "iag.submit_request",
    }


def test_tool_call_allow_and_approval_round_trip(client: TestClient, estate: DemoEstate) -> None:
    token = _token(client, estate, "access-request", "iag")
    read = _rpc(
        client,
        estate,
        "access-request",
        "iag",
        token,
        "tools/call",
        {"name": "catalog.search_roles", "arguments": {"query": "vendor"}},
    )
    assert read["result"]["isError"] is False
    assert read["result"]["_meta"]["governance"]["verdict"] == "allow"

    call = {
        "name": "iag.submit_request",
        "arguments": {"roles": ["Z_VENDOR_DISPLAY"], "end_date": "2026-11-15"},
    }
    parked = _rpc(client, estate, "access-request", "iag", token, "tools/call", call)["result"]
    assert parked["isError"] is True
    task_id = parked["structuredContent"]["approval_task_id"]

    mark = {"Authorization": f"Bearer {estate.user_token('user:mark@acme')}"}
    inbox = client.get("/approvals", headers=mark).json()["tasks"]
    assert [t["task_id"] for t in inbox] == [task_id]
    assert (
        client.get(
            "/approvals", headers={"Authorization": f"Bearer {estate.user_token('user:sam@acme')}"}
        ).json()["tasks"]
        == []
    )
    sam = {"Authorization": f"Bearer {estate.user_token('user:sam@acme')}"}
    assert client.get(f"/approvals/{task_id}", headers=sam).status_code == 404  # not theirs to see
    assert (
        client.post(f"/approvals/{task_id}/reject", json={"reason": "x"}, headers=sam).status_code
        == 403
    )
    priya = {"Authorization": f"Bearer {estate.user_token(PRIYA)}"}
    assert (
        client.get(f"/approvals/{task_id}", headers=priya).status_code == 200
    )  # the requester can
    approval = client.post(
        f"/approvals/{task_id}/approve", json={"role": "line_manager"}, headers=mark
    ).json()["approval"]

    done = _rpc(
        client,
        estate,
        "access-request",
        "iag",
        token,
        "tools/call",
        {**call, "_meta": {"approvals": [approval]}},
    )
    assert done["result"]["_meta"]["governance"]["verdict"] == "allow"
    assert done["result"]["structuredContent"]["status"] == "submitted"


def test_tool_call_with_stolen_token_is_denied(client: TestClient, estate: DemoEstate) -> None:
    token = _token(client, estate, "access-request", "iag")
    # proof signed by a different agent's key
    body = _rpc(
        client,
        estate,
        "ap-automation",
        "iag",
        token,
        "tools/call",
        {"name": "catalog.search_roles", "arguments": {}},
    )
    assert body["result"]["isError"] is True
    assert "DPoP" in body["result"]["structuredContent"]["reason"]


def test_mcp_protocol_errors(client: TestClient, estate: DemoEstate) -> None:
    token = _token(client, estate, "access-request", "iag")
    assert client.post("/mcp/iag", content=b"{nope").json()["error"]["code"] == -32700
    assert client.post("/mcp/iag", json={"id": 1}).json()["error"]["code"] == -32600
    no_auth = client.post("/mcp/iag", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert no_auth.json()["error"]["code"] == -32001
    assert (
        _rpc(client, estate, "access-request", "nope", token, "tools/list", {})["error"]["code"]
        == -32601
    )
    wrong_server = _rpc(
        client, estate, "access-request", "iag", token, "tools/call", {"name": "s4.vendor_get"}
    )
    assert wrong_server["error"]["code"] == -32602
    assert (
        _rpc(client, estate, "access-request", "iag", token, "initialize", {})["result"][
            "serverInfo"
        ]["name"]
        == "agent-governance/iag"
    )
    assert (
        _rpc(client, estate, "access-request", "iag", token, "resources/list", {})["error"]["code"]
        == -32601
    )


def test_approval_api_errors(client: TestClient, estate: DemoEstate) -> None:
    assert client.get("/approvals").status_code == 401
    mark = {"Authorization": f"Bearer {estate.user_token('user:mark@acme')}"}
    assert client.get("/approvals/apt_nope", headers=mark).status_code == 404
    assert (
        client.post("/approvals/apt_nope/reject", json={"reason": "x"}, headers=mark).status_code
        == 404
    )


def test_sod_and_evidence_apis_require_entitlements(client: TestClient, estate: DemoEstate) -> None:
    sam = {"Authorization": f"Bearer {estate.user_token('user:sam@acme')}"}
    static = client.post("/sod/static", json={"principal_id": "user:sam@acme"}, headers=sam).json()
    assert [v["risk_id"] for v in static["violations"]] == ["P2P-01"]
    sim = client.post(
        "/sod/simulate",
        json={"principal_id": "user:sam@acme", "remove_roles": ["Z_AP_CLERK"]},
        headers=sam,
    )
    assert [v["risk_id"] for v in sim.json()["removed"]] == ["P2P-01"]
    assert (
        client.post("/sod/static", json={"principal_id": "user:ghost"}, headers=sam).status_code
        == 404
    )
    assert (
        client.get("/evidence/verify", params={"day": "2026-10-27"}, headers=sam).status_code == 403
    )

    cora = {"Authorization": f"Bearer {estate.user_token('user:cora@acme')}"}
    assert (
        client.get("/evidence/verify", params={"day": "2026-10-27"}, headers=cora).json()["ok"]
        is True
    )
    packet = client.post(
        "/evidence/packets",
        json={"control_id": "AC-ID-01", "start": "2026-10-27", "end": "2026-10-27"},
        headers=cora,
    )
    assert packet.status_code == 200
    assert packet.json()["control"]["id"] == "AC-ID-01"
    bad = client.post(
        "/evidence/packets",
        json={"control_id": "NOPE", "start": "2026-10-27", "end": "2026-10-27"},
        headers=cora,
    )
    assert bad.status_code == 400


def test_suspended_user_cannot_use_human_apis(client: TestClient, estate: DemoEstate) -> None:
    leo = {"Authorization": f"Bearer {estate.user_token('user:leo@acme')}"}
    assert client.get("/approvals", headers=leo).status_code == 401
