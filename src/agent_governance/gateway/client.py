# SPDX-License-Identifier: Apache-2.0
"""Agent-side helper: hold a key, exchange tokens and make DPoP-signed gateway calls.

``AgentClient`` drives an in-process :class:`~agent_governance.runtime.Runtime`; the HTTP
surface accepts the same tokens and proofs, so swapping transports does not change the
security properties under test.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from agent_governance.gateway.gateway import GatewayResult, ToolCall
from agent_governance.identity.dpop import make_proof
from agent_governance.identity.idp import make_client_assertion
from agent_governance.identity.sts import ExchangeRequest, IssuedToken
from agent_governance.runtime import Runtime


@dataclass
class AgentClient:
    runtime: Runtime
    principal_id: str
    key: ec.EllipticCurvePrivateKey

    def exchange(
        self,
        subject_token: str | None,
        audience: str,
        *,
        plan_id: str | None = None,
        scope: Sequence[str] | None = None,
        session_id: str | None = None,
        proof_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> IssuedToken:
        settings = self.runtime.settings
        clock = self.runtime.clock
        return self.runtime.tokens.exchange(
            ExchangeRequest(
                subject_token=subject_token,
                actor_token=make_client_assertion(
                    self.key, self.principal_id, settings.token_endpoint, clock
                ),
                audience=audience,
                dpop_proof=make_proof(
                    proof_key or self.key, "POST", settings.token_endpoint, clock=clock
                ),
                token_endpoint=settings.token_endpoint,
                scope=scope,
                plan_id=plan_id,
                session_id=session_id,
            )
        )

    def call(
        self,
        token: IssuedToken | str,
        tool_id: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        approvals: Sequence[str] = (),
        proof_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> GatewayResult:
        access = token if isinstance(token, str) else token.access_token
        tool = self.runtime.tools.get(tool_id)
        url = self.runtime.settings.mcp_url(tool.server)
        proof = make_proof(
            proof_key or self.key, "POST", url, clock=self.runtime.clock, access_token=access
        )
        return self.runtime.gateway.handle(
            ToolCall(
                tool_id=tool_id,
                arguments=dict(arguments or {}),
                access_token=access,
                dpop_proof=proof,
                htu=url,
                approvals=tuple(approvals),
            )
        )
