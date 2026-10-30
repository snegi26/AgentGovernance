# SPDX-License-Identifier: Apache-2.0
"""HTTP client an agent process uses to exchange tokens and call tools through the gateway.

The client is built from the gateway's public URL and the agent's own private key. It never
sees the runtime, its service keys or another agent's key, so code running in the agent
process cannot sign approvals or mint tokens, whatever a model tells it to do.

Requests follow the gateway's HTTP surface (``agent_governance.gateway.http``):

* ``POST /token``: RFC 8693 exchange, with a ``private_key_jwt`` actor assertion and a DPoP
  proof for the token endpoint;
* ``POST /mcp/{server}``: MCP JSON-RPC, with ``Authorization: DPoP <token>`` and a fresh proof
  bound to that token and URL. The server is the token's audience, so one token serves one
  tool server.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric import ec

from agent_governance.core import Clock, SystemClock
from agent_governance.identity.dpop import make_proof
from agent_governance.identity.idp import make_client_assertion

#: RFC 8693 identifiers, repeated here so agent code does not import the token service.
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - URN
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"  # noqa: S105 - URN


class GatewayClientError(RuntimeError):
    """The gateway refused the request before deciding on it, or answered malformed."""


class TokenExchangeFailedError(GatewayClientError):
    def __init__(self, error: str, description: str) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description


class RpcError(GatewayClientError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class RemoteToken:
    access_token: str
    audience: str
    scope: tuple[str, ...]
    expires_in: int


@dataclass(frozen=True, slots=True)
class RemoteResult:
    """The gateway's decision on one tool call, as the agent sees it."""

    verdict: str
    reason: str
    tool_id: str
    result: Mapping[str, Any] | None = None
    approval_task_id: str | None = None
    tier: str = "none"
    evidence_id: str | None = None
    sod_result_ref: str | None = None
    shadow: bool = False
    flags: tuple[str, ...] = ()
    governance: Mapping[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


@dataclass
class RemoteAgentClient:
    """An agent's only route to the governance service.

    ``http`` is any ``httpx.Client``; production passes one with TLS settings, tests pass the
    FastAPI test client. ``base_url`` must be the gateway's configured public URL, because DPoP
    proofs are checked against it.
    """

    base_url: str
    principal_id: str
    key: ec.EllipticCurvePrivateKey
    http: httpx.Client
    clock: Clock = field(default_factory=SystemClock)
    _ids: itertools.count[int] = field(default_factory=itertools.count, init=False, repr=False)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    @property
    def token_endpoint(self) -> str:
        return f"{self.base_url}/token"

    def mcp_url(self, server: str) -> str:
        return f"{self.base_url}/mcp/{server}"

    # -- token exchange ---------------------------------------------------------------------------

    def exchange(
        self,
        subject_token: str,
        audience: str,
        *,
        plan_id: str,
        scope: Sequence[str] | None = None,
        session_id: str | None = None,
    ) -> RemoteToken:
        """Exchange a delegator's token (a user's or a trigger's) for a tool-server token."""
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token,
            "subject_token_type": TOKEN_TYPE_JWT,
            "actor_token": make_client_assertion(
                self.key, self.principal_id, self.token_endpoint, self.clock
            ),
            "actor_token_type": TOKEN_TYPE_JWT,
            "audience": audience,
            "plan_id": plan_id,
        }
        if scope is not None:
            form["scope"] = " ".join(scope)
        if session_id is not None:
            form["session_id"] = session_id
        proof = make_proof(self.key, "POST", self.token_endpoint, clock=self.clock)
        response = self.http.post(self.token_endpoint, data=form, headers={"DPoP": proof})
        body = self._json(response)
        if response.status_code != httpx.codes.OK:
            raise TokenExchangeFailedError(
                str(body.get("error", "server_error")), str(body.get("error_description", ""))
            )
        if body.get("token_type") != "DPoP":
            raise GatewayClientError("the gateway issued a token that is not DPoP-bound")
        return RemoteToken(
            access_token=str(body["access_token"]),
            audience=audience,
            scope=tuple(str(body.get("scope", "")).split()),
            expires_in=int(body["expires_in"]),
        )

    # -- MCP --------------------------------------------------------------------------------------

    def list_tools(self, token: RemoteToken) -> list[dict[str, Any]]:
        result = self._rpc(token, "tools/list", {})
        return [dict(t) for t in result.get("tools", [])]

    def call(
        self,
        token: RemoteToken,
        tool_id: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        approvals: Sequence[str] = (),
    ) -> RemoteResult:
        """Call a tool on the token's server; approvals are signed approval tokens to present."""
        params: dict[str, Any] = {"name": tool_id, "arguments": dict(arguments or {})}
        if approvals:
            params["_meta"] = {"approvals": list(approvals)}
        result = self._rpc(token, "tools/call", params)
        governance = (result.get("_meta") or {}).get("governance")
        if not isinstance(governance, Mapping):
            raise GatewayClientError("tool result carries no governance decision")
        allowed = governance.get("verdict") == "allow"
        payload = result.get("structuredContent") if allowed else None
        return RemoteResult(
            verdict=str(governance["verdict"]),
            reason=str(governance.get("reason", "")),
            tool_id=str(governance.get("tool_id", tool_id)),
            result=dict(payload) if isinstance(payload, Mapping) else None,
            approval_task_id=governance.get("approval_task_id"),
            tier=str(governance.get("tier", "none")),
            evidence_id=governance.get("evidence_id"),
            sod_result_ref=governance.get("sod_result_ref"),
            shadow=bool(governance.get("shadow", False)),
            flags=tuple(governance.get("flags", ())),
            governance=dict(governance),
        )

    def _rpc(self, token: RemoteToken, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        url = self.mcp_url(token.audience)
        proof = make_proof(self.key, "POST", url, clock=self.clock, access_token=token.access_token)
        request_id = next(self._ids)
        response = self.http.post(
            url,
            json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)},
            headers={"Authorization": f"DPoP {token.access_token}", "DPoP": proof},
        )
        body = self._json(response)
        if response.status_code != httpx.codes.OK:
            raise GatewayClientError(f"gateway answered HTTP {response.status_code}")
        if body.get("id") != request_id:
            raise GatewayClientError("JSON-RPC response id does not match the request")
        error = body.get("error")
        if isinstance(error, Mapping):
            raise RpcError(int(error.get("code", 0)), str(error.get("message", "")))
        result = body.get("result")
        if not isinstance(result, dict):
            raise GatewayClientError("JSON-RPC response has no result")
        return result

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError as exc:
            raise GatewayClientError(
                f"gateway answered non-JSON (HTTP {response.status_code})"
            ) from exc
        if not isinstance(body, dict):
            raise GatewayClientError("gateway answered a JSON value that is not an object")
        return body
