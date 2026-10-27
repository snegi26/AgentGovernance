# SPDX-License-Identifier: Apache-2.0
"""HTTP surface: token exchange, MCP tool calls, approvals, SoD and evidence APIs.

* ``POST /token`` — RFC 8693 token exchange (form-encoded) with a ``DPoP`` header.
* ``POST /mcp/{server}`` — MCP JSON-RPC (``initialize``, ``tools/list``, ``tools/call``)
  with ``Authorization: DPoP <token>`` and a ``DPoP`` proof for this exact URL.
* ``/approvals`` — approver inbox and decisions, authenticated with an IdP bearer token.
* ``/sod/*`` and ``/evidence/*`` — read APIs for role owners and auditors.

Every URL the gateway checks DPoP ``htu`` against is the configured *public* URL
(``Settings.base_url``), never the Host header, so a proxy cannot redirect proofs.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import date
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agent_governance import __version__
from agent_governance.approval.service import ApprovalError
from agent_governance.approval.tiers import ApproverRole
from agent_governance.gateway.gateway import ToolCall, Verdict
from agent_governance.identity.dpop import DpopError
from agent_governance.identity.sts import ExchangeRequest, InvalidTokenError, TokenExchangeError
from agent_governance.model import Principal, UnknownEntityError
from agent_governance.runtime import Runtime

MCP_PROTOCOL_VERSION = "2025-06-18"
AUDIT_ENTITLEMENT = "audit.read_evidence"
SOD_ENTITLEMENT = "governance.use_assistant"


class ApproveBody(BaseModel):
    role: ApproverRole


class RejectBody(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class StaticBody(BaseModel):
    principal_id: str


class SimulateBody(BaseModel):
    principal_id: str
    add_roles: list[str] = Field(default_factory=list)
    remove_roles: list[str] = Field(default_factory=list)


class PacketBody(BaseModel):
    control_id: str
    start: date
    end: date


def _oauth_error(status: int, error: str, description: str) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def _rpc_error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def create_app(runtime: Runtime) -> FastAPI:
    app = FastAPI(
        title="Agent Governance Gateway",
        version=__version__,
        description="Deterministic access governance for human, non-human and AI-agent identities.",
    )
    settings = runtime.settings

    def user(authorization: str | None, entitlement: str | None = None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "a Bearer token from the identity provider is required")
        try:
            principal = runtime.tokens.verify_user_token(
                authorization.removeprefix("Bearer ").strip()
            )
        except InvalidTokenError as exc:
            raise HTTPException(401, str(exc)) from exc
        if entitlement is not None and entitlement not in principal.entitlements:
            raise HTTPException(403, f"missing entitlement {entitlement}")
        return principal

    # -- discovery ------------------------------------------------------------------------------

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "tenant": settings.tenant}

    @app.get("/.well-known/jwks.json")
    def jwks() -> dict[str, Any]:
        return runtime.tokens.jwks()

    # -- token exchange ---------------------------------------------------------------------------

    @app.post("/token")
    async def token(request: Request, dpop: str | None = Header(default=None)) -> JSONResponse:
        if (
            request.headers.get("content-type", "").split(";")[0]
            != "application/x-www-form-urlencoded"
        ):
            return _oauth_error(400, "invalid_request", "use application/x-www-form-urlencoded")
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        scope = form.get("scope")
        try:
            issued = runtime.tokens.exchange(
                ExchangeRequest(
                    grant_type=form.get("grant_type", ""),
                    subject_token=form.get("subject_token"),
                    subject_token_type=form.get("subject_token_type", ""),
                    actor_token=form.get("actor_token"),
                    actor_token_type=form.get("actor_token_type", ""),
                    audience=form.get("audience", ""),
                    scope=scope.split() if scope else None,
                    session_id=form.get("session_id"),
                    plan_id=form.get("plan_id"),
                    dpop_proof=dpop,
                    token_endpoint=settings.token_endpoint,
                )
            )
        except TokenExchangeError as exc:
            status = (
                401
                if exc.error == "invalid_client"
                else 503
                if exc.error == "temporarily_unavailable"
                else 400
            )
            return _oauth_error(status, exc.error, exc.description)
        return JSONResponse(issued.to_response(), headers={"Cache-Control": "no-store"})

    # -- MCP --------------------------------------------------------------------------------------

    @app.post("/mcp/{server}")
    async def mcp(
        server: str,
        request: Request,
        authorization: str | None = Header(default=None),
        dpop: str | None = Header(default=None),
    ) -> dict[str, Any]:
        try:
            message = json.loads(await request.body())
        except json.JSONDecodeError:
            return _rpc_error(None, -32700, "parse error")
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _rpc_error(None, -32600, "invalid request")
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}
        if server not in runtime.tools.servers():
            return _rpc_error(request_id, -32601, f"unknown tool server {server!r}")
        access = (authorization or "").removeprefix("DPoP ").strip() if authorization else ""
        if not authorization or not authorization.startswith("DPoP ") or not access:
            return _rpc_error(request_id, -32001, "Authorization: DPoP <token> is required")
        url = settings.mcp_url(server)

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": f"agent-governance/{server}", "version": __version__},
                },
            }
        if method == "tools/list":
            try:
                claims = runtime.tokens.verify_access_token(access, audience=server)
                runtime.dpop.verify(
                    dpop, htm="POST", htu=url, access_token=access, expected_jkt=claims.jkt
                )
            except (InvalidTokenError, DpopError) as exc:
                return _rpc_error(request_id, -32001, str(exc))
            tools = [
                {
                    "name": t.tool_id,
                    "description": t.description,
                    "inputSchema": {"type": "object"},
                    "annotations": {
                        "readOnlyHint": not t.action_class.is_write,
                        "destructiveHint": t.action_class.is_write,
                    },
                }
                for t in runtime.tools.for_server(server)
                if t.tool_id in claims.scope
            ]
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}}
        if method != "tools/call":
            return _rpc_error(request_id, -32601, f"method {method!r} not supported")

        name = params.get("name")
        tool = runtime.tools.find(str(name)) if name else None
        if tool is None or tool.server != server:
            return _rpc_error(request_id, -32602, f"tool {name!r} is not served at /mcp/{server}")
        arguments = params.get("arguments") or {}
        approvals = (params.get("_meta") or {}).get("approvals") or []
        if not isinstance(arguments, dict) or not isinstance(approvals, list):
            return _rpc_error(
                request_id, -32602, "arguments must be an object and approvals a list"
            )
        result = runtime.gateway.handle(
            ToolCall(
                tool_id=tool.tool_id,
                arguments=arguments,
                access_token=access,
                dpop_proof=dpop,
                htu=url,
                approvals=[str(a) for a in approvals],
            )
        )
        governance = result.to_dict()
        governance.pop("result")
        if result.verdict is Verdict.ALLOW:
            payload = dict(result.result or {})
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload)}],
                    "structuredContent": payload,
                    "isError": "error" in payload,
                    "_meta": {"governance": governance},
                },
            }
        text = (
            f"Approval required ({result.tier.value}); task {result.approval_task_id}. "
            "Resubmit the identical call with the signed approvals in _meta.approvals."
            if result.verdict is Verdict.REQUIRE_APPROVAL
            else f"Denied: {result.reason}"
        )
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "structuredContent": governance,
                "isError": True,
                "_meta": {"governance": governance},
            },
        }

    # -- approvals --------------------------------------------------------------------------------

    def approval_call(fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except ApprovalError as exc:
            status = 404 if "unknown approval task" in str(exc) else 409
            raise HTTPException(status, str(exc)) from exc

    @app.get("/approvals")
    def list_approvals(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        approver = user(authorization)
        tasks = [
            t.to_dict()
            for t in runtime.approvals.pending()
            if any(
                runtime.directory.holds(approver.id, r, delegator=t.delegator)
                for r in t.outstanding_roles
            )
        ]
        return {"tasks": tasks}

    @app.get("/approvals/{task_id}")
    def get_approval(
        task_id: str, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        user(authorization)
        task = approval_call(lambda: runtime.approvals.task(task_id))
        return dict(task.to_dict())

    @app.post("/approvals/{task_id}/approve")
    def approve(
        task_id: str, body: ApproveBody, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        approver = user(authorization)
        token = approval_call(lambda: runtime.approvals.approve(task_id, approver.id, body.role))
        return {"approval": token, "task": runtime.approvals.task(task_id).to_dict()}

    @app.post("/approvals/{task_id}/reject")
    def reject(
        task_id: str, body: RejectBody, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        approver = user(authorization)
        task = approval_call(lambda: runtime.approvals.reject(task_id, approver.id, body.reason))
        return dict(task.to_dict())

    # -- SoD and evidence -----------------------------------------------------------------------

    @app.post("/sod/static")
    def sod_static(
        body: StaticBody, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        user(authorization, SOD_ENTITLEMENT)
        try:
            return runtime.sod.static(body.principal_id).to_dict()
        except UnknownEntityError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/sod/simulate")
    def sod_simulate(
        body: SimulateBody, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        user(authorization, SOD_ENTITLEMENT)
        try:
            return runtime.sod.simulate(
                body.principal_id, body.add_roles, body.remove_roles
            ).to_dict()
        except UnknownEntityError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/evidence/verify")
    def evidence_verify(
        day: date, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        user(authorization, AUDIT_ENTITLEMENT)
        result = runtime.evidence.verify(settings.tenant, day)
        return {
            "day": result.day,
            "ok": result.ok,
            "count": result.count,
            "root": result.root,
            "first_bad_record": result.first_bad_record,
            "error": result.error,
        }

    @app.post("/evidence/packets")
    def evidence_packet(
        body: PacketBody, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        user(authorization, AUDIT_ENTITLEMENT)
        try:
            return runtime.packet(body.control_id, body.start, body.end)
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc)) from exc

    return app
