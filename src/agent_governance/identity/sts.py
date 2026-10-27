# SPDX-License-Identifier: Apache-2.0
"""Security token service: RFC 8693 token exchange into delegated, DPoP-bound agent tokens.

Every agent token has two subjects: ``sub`` is the agent, and the (possibly nested) ``act``
claim is the chain of principals it acts for, ending at a human (on-behalf-of) or a registered
trigger (triggered). There is no autonomous mode: an exchange without a subject token is
refused, so there is no token an agent can hold on its own authority.

Token rules enforced here:

* lifetime at most 5 minutes; audience is exactly one tool server;
* ``scope`` lists tool IDs = requested ∩ agent contract ∩ tools on that server ∩ autonomy,
  further ∩ the trigger envelope for triggered work;
* ``cnf.jkt`` binds the token to the agent's registered key (DPoP);
* chained delegation nests ``act`` claims, depth at most 3, with no agent appearing twice;
* ``session_id`` and ``plan_id`` are always present; a sub-agent inherits the ``plan_id``.

Note on ``act`` orientation: RFC 8693 puts the *acting* party in ``act`` and the subject in
``sub``. The build spec deliberately inverts this (``sub`` = agent, ``act`` = principal it acts
for) so that ``sub`` always names the caller the gateway is authorizing. This module follows
the spec and documents the inversion rather than silently mixing the two.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agent_governance.core import Clock, SystemClock, new_id
from agent_governance.crypto import ec_public_jwk, ec_public_key_from_jwk, jwk_thumbprint
from agent_governance.evidence.record import EvidenceKind
from agent_governance.evidence.store import EvidenceSink, EvidenceUnavailableError
from agent_governance.identity.dpop import DpopError, DpopVerifier
from agent_governance.identity.idp import IssuerKind, TrustedIssuer
from agent_governance.identity.registry import (
    AgentContract,
    AgentRegistry,
    TriggerRegistration,
    UnknownAgentError,
)
from agent_governance.identity.revocation import RevocationList
from agent_governance.model import Inventory, Principal, PrincipalKind
from agent_governance.policy.tools import ToolCatalog

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - URN, not a secret
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"  # noqa: S105
TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105
MAX_LIFETIME = timedelta(minutes=5)
MAX_DELEGATION_DEPTH = 3
_SKEW = 5


class TokenExchangeError(Exception):
    """An OAuth error response: ``error`` is the RFC 6749 / 8693 error code."""

    def __init__(self, error: str, description: str) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description


class InvalidTokenError(Exception):
    """An access token presented to the gateway is invalid, expired, revoked or misbound."""


@dataclass(frozen=True, slots=True)
class ExchangeRequest:
    subject_token: str | None
    actor_token: str | None
    audience: str
    dpop_proof: str | None
    token_endpoint: str
    scope: Sequence[str] | None = None
    session_id: str | None = None
    plan_id: str | None = None
    grant_type: str = TOKEN_EXCHANGE_GRANT
    subject_token_type: str = TOKEN_TYPE_JWT
    actor_token_type: str = TOKEN_TYPE_JWT


@dataclass(frozen=True, slots=True)
class Delegation:
    """``chain`` runs from the agent's immediate delegator inward to the root principal."""

    chain: tuple[str, ...]
    root_kind: PrincipalKind

    @property
    def root(self) -> str:
        return self.chain[-1]

    @property
    def depth(self) -> int:
        return len(self.chain)


@dataclass(frozen=True, slots=True)
class AccessClaims:
    raw: Mapping[str, Any]
    subject: str
    audience: str
    scope: frozenset[str]
    jti: str
    session_id: str
    plan_id: str
    jkt: str
    tenant: str
    delegation: Delegation
    iat: int
    exp: int


@dataclass(frozen=True, slots=True)
class IssuedToken:
    access_token: str
    expires_in: int
    scope: tuple[str, ...]
    claims: Mapping[str, Any] = field(default_factory=dict)
    token_type: str = "DPoP"  # noqa: S105
    issued_token_type: str = TOKEN_TYPE_ACCESS

    def to_response(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "issued_token_type": self.issued_token_type,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "scope": " ".join(self.scope),
        }


def act_chain(claims: Mapping[str, Any]) -> list[str]:
    chain: list[str] = []
    act = claims.get("act")
    while isinstance(act, Mapping):
        chain.append(str(act["sub"]))
        act = act.get("act")
    return chain


def _nest(chain: Sequence[str]) -> dict[str, Any]:
    act: dict[str, Any] | None = None
    for principal in reversed(chain):
        act = {"sub": principal} if act is None else {"sub": principal, "act": act}
    assert act is not None
    return act


class TokenService:
    def __init__(
        self,
        *,
        issuer: str,
        tenant: str,
        signing_key: ec.EllipticCurvePrivateKey,
        registry: AgentRegistry,
        inventory: Inventory,
        tools: ToolCatalog,
        trusted_issuers: Iterable[TrustedIssuer],
        revocations: RevocationList,
        dpop: DpopVerifier,
        evidence: EvidenceSink,
        clock: Clock | None = None,
        lifetime: timedelta = MAX_LIFETIME,
    ) -> None:
        if lifetime > MAX_LIFETIME:
            raise ValueError("token lifetime may not exceed 5 minutes")
        self.issuer = issuer
        self.tenant = tenant
        self._key = signing_key
        self._kid = jwk_thumbprint(ec_public_jwk(signing_key))
        self.registry = registry
        self.inventory = inventory
        self.tools = tools
        self._issuers = {i.issuer: i for i in trusted_issuers}
        self.revocations = revocations
        self.dpop = dpop
        self.evidence = evidence
        self.clock = clock or SystemClock()
        self.lifetime = lifetime
        self._assertions_seen: dict[str, int] = {}
        self._lock = threading.Lock()

    # -- discovery --------------------------------------------------------------------------

    def jwks(self) -> dict[str, Any]:
        return {
            "keys": [{**ec_public_jwk(self._key), "kid": self._kid, "alg": "ES256", "use": "sig"}]
        }

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        return self._key.public_key()

    # -- exchange ---------------------------------------------------------------------------

    def exchange(self, request: ExchangeRequest) -> IssuedToken:
        try:
            issued = self._exchange(request)
        except TokenExchangeError as exc:
            self._record_refusal(request, exc)
            raise
        return issued

    def _exchange(self, req: ExchangeRequest) -> IssuedToken:
        if req.grant_type != TOKEN_EXCHANGE_GRANT:
            raise TokenExchangeError("unsupported_grant_type", "only token exchange is supported")
        if not req.subject_token:
            raise TokenExchangeError(
                "invalid_request",
                "a subject token is required; autonomous delegation is not supported",
            )
        if not req.actor_token:
            raise TokenExchangeError(
                "invalid_request", "an actor token identifying the agent is required"
            )

        agent = self._verify_actor(req.actor_token, req.token_endpoint)
        subject = self._verify_subject(req.subject_token)
        if subject.parent is not None:
            # Hand-off: the current holder of the subject token proves possession, and the
            # delegating agent's contract must name the receiving agent.
            expected_jkt = subject.parent.jkt
            if agent.principal_id in (subject.parent.subject, *subject.parent.delegation.chain):
                raise TokenExchangeError(
                    "invalid_request", "an agent may not appear twice in a chain"
                )
            parent_contract = self.registry.get(subject.parent.subject)
            if agent.agent_id not in parent_contract.may_delegate_to:
                raise TokenExchangeError(
                    "invalid_request",
                    f"{parent_contract.principal_id} may not hand off to {agent.agent_id}",
                )
        else:
            expected_jkt = agent.key_thumbprint
        trigger = subject.trigger
        if (
            trigger is not None
            and trigger.agents
            and subject.parent is None
            and agent.principal_id not in trigger.agents
        ):
            raise TokenExchangeError(
                "invalid_request",
                f"trigger {trigger.trigger_id} may not start {agent.principal_id}",
            )
        try:
            self.dpop.verify(
                req.dpop_proof, htm="POST", htu=req.token_endpoint, expected_jkt=expected_jkt
            )
        except DpopError as exc:
            raise TokenExchangeError("invalid_dpop_proof", str(exc)) from exc

        if subject.delegation.depth > MAX_DELEGATION_DEPTH:
            raise TokenExchangeError(
                "invalid_request", f"delegation depth exceeds {MAX_DELEGATION_DEPTH}"
            )
        if req.audience not in self.tools.servers():
            raise TokenExchangeError("invalid_target", f"unknown tool server {req.audience!r}")

        scope = self._scope(agent, req, subject)
        plan_id = req.plan_id or (subject.parent.plan_id if subject.parent else None)
        if not plan_id:
            raise TokenExchangeError("invalid_request", "plan_id is required")
        if subject.parent is not None and plan_id != subject.parent.plan_id:
            raise TokenExchangeError(
                "invalid_request", "a hand-off must stay in the delegating plan"
            )

        now = int(self.clock.now().timestamp())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": agent.principal_id,
            "aud": req.audience,
            "iat": now,
            "nbf": now,
            "exp": now + int(self.lifetime.total_seconds()),
            "jti": new_id("at"),
            "scope": " ".join(scope),
            "act": _nest(subject.delegation.chain),
            "cnf": {"jkt": agent.key_thumbprint},
            "session_id": req.session_id or new_id("sess"),
            "plan_id": plan_id,
            "tenant": self.tenant,
            "delegator_kind": subject.delegation.root_kind.value,
        }
        token = jwt.encode(claims, self._key, algorithm="ES256", headers={"kid": self._kid})
        try:
            self.evidence.append(
                self.tenant,
                EvidenceKind.TOKEN_EXCHANGE,
                actor={"agent": agent.principal_id, "delegator": subject.delegation.root},
                verdict="issued",
                session_id=claims["session_id"],
                plan_id=plan_id,
                details={
                    "jti": claims["jti"],
                    "aud": req.audience,
                    "scope": list(scope),
                    "act_chain": list(subject.delegation.chain),
                    "exp": claims["exp"],
                },
            )
        except EvidenceUnavailableError as exc:
            raise TokenExchangeError(
                "temporarily_unavailable", "evidence store unavailable"
            ) from exc
        return IssuedToken(token, int(self.lifetime.total_seconds()), scope, claims)

    def _verify_actor(self, actor_token: str, token_endpoint: str) -> AgentContract:
        try:
            unverified = jwt.decode(actor_token, options={"verify_signature": False})
            agent = self.registry.get(str(unverified["sub"]))
        except (jwt.PyJWTError, KeyError, UnknownAgentError) as exc:
            raise TokenExchangeError(
                "invalid_client", "unknown or malformed agent assertion"
            ) from exc
        if not agent.active:
            raise TokenExchangeError("invalid_client", f"{agent.principal_id} is retired")
        try:
            claims = jwt.decode(
                actor_token,
                ec_public_key_from_jwk(agent.public_jwk),
                algorithms=["ES256"],
                audience=token_endpoint,
                options={
                    "require": ["iss", "sub", "aud", "exp", "jti"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenExchangeError("invalid_client", f"agent assertion rejected: {exc}") from exc
        if claims["iss"] != claims["sub"]:
            raise TokenExchangeError(
                "invalid_client", "assertion iss and sub must both name the agent"
            )
        now = int(self.clock.now().timestamp())
        if int(claims["exp"]) < now - _SKEW:
            raise TokenExchangeError("invalid_client", "agent assertion expired")
        with self._lock:
            self._assertions_seen = {
                j: e for j, e in self._assertions_seen.items() if e >= now - _SKEW
            }
            if claims["jti"] in self._assertions_seen:
                raise TokenExchangeError("invalid_client", "agent assertion replayed")
            self._assertions_seen[str(claims["jti"])] = int(claims["exp"])
        return agent

    @dataclass(frozen=True, slots=True)
    class _Subject:
        delegation: Delegation
        trigger: TriggerRegistration | None
        parent: AccessClaims | None

        @property
        def envelope(self) -> frozenset[str] | None:
            return self.trigger.envelope if self.trigger is not None else None

    def _verify_subject(self, subject_token: str) -> TokenService._Subject:
        try:
            issuer = str(jwt.decode(subject_token, options={"verify_signature": False})["iss"])
        except (jwt.PyJWTError, KeyError) as exc:
            raise TokenExchangeError("invalid_grant", "malformed subject token") from exc

        if issuer == self.issuer:
            try:
                parent = self.verify_access_token(subject_token)
            except InvalidTokenError as exc:
                raise TokenExchangeError("invalid_grant", f"subject token rejected: {exc}") from exc
            chain = (parent.subject, *parent.delegation.chain)
            trigger = None
            if parent.delegation.root_kind is PrincipalKind.TRIGGER:
                trigger = self._trigger(parent.delegation.root)
            return TokenService._Subject(
                Delegation(chain, parent.delegation.root_kind), trigger, parent
            )

        try:
            trusted, claims = self._verify_external(subject_token, issuer)
        except InvalidTokenError as exc:
            raise TokenExchangeError("invalid_grant", str(exc)) from exc
        subject = str(claims["sub"])

        if trusted.kind is IssuerKind.IDP:
            principal = self.inventory.find_principal(subject)
            if (
                principal is None
                or principal.kind is not PrincipalKind.HUMAN
                or not principal.active
            ):
                raise TokenExchangeError(
                    "invalid_grant", "subject is not an active human principal"
                )
            return TokenService._Subject(Delegation((subject,), PrincipalKind.HUMAN), None, None)

        if not subject.startswith("trigger:"):
            raise TokenExchangeError("invalid_grant", "event subject must name a trigger")
        return TokenService._Subject(
            Delegation((subject,), PrincipalKind.TRIGGER), self._trigger(subject), None
        )

    def _trigger(self, trigger_principal: str) -> TriggerRegistration:
        trigger_id = trigger_principal.removeprefix("trigger:")
        try:
            trigger = self.registry.trigger(trigger_id)
        except UnknownAgentError as exc:
            raise TokenExchangeError(
                "invalid_grant", f"unregistered trigger {trigger_id!r}"
            ) from exc
        if not trigger.enabled:
            raise TokenExchangeError("invalid_grant", f"trigger {trigger_id!r} is disabled")
        return trigger

    def _scope(
        self, agent: AgentContract, req: ExchangeRequest, subject: TokenService._Subject
    ) -> tuple[str, ...]:
        server_tools = {t.tool_id: t for t in self.tools.for_server(req.audience)}
        requested = set(req.scope) if req.scope is not None else set(server_tools)
        granted = {
            tool_id
            for tool_id in requested & agent.allowed_tools
            if tool_id in server_tools
            and server_tools[tool_id].action_class.autonomy_rank <= agent.max_autonomy.rank
        }
        if subject.envelope is not None:
            granted &= subject.envelope
        if not granted:
            raise TokenExchangeError(
                "invalid_scope", "no requested tool is permitted for this agent and delegator"
            )
        return tuple(sorted(granted))

    def _record_refusal(self, req: ExchangeRequest, exc: TokenExchangeError) -> None:
        try:
            agent = (
                jwt.decode(req.actor_token, options={"verify_signature": False}).get("sub")
                if req.actor_token
                else None
            )
        except jwt.PyJWTError:
            agent = None
        # The exchange already failed closed; a missing refusal record protects nothing more.
        with contextlib.suppress(EvidenceUnavailableError):
            self.evidence.append(
                self.tenant,
                EvidenceKind.TOKEN_EXCHANGE,
                actor={"agent": str(agent) if agent else None, "delegator": None},
                verdict="refused",
                plan_id=req.plan_id,
                flags=(exc.error,),
                details={"aud": req.audience, "reason": exc.description},
            )

    def _verify_external(self, token: str, issuer: str) -> tuple[TrustedIssuer, dict[str, Any]]:
        trusted = self._issuers.get(issuer)
        if trusted is None:
            raise InvalidTokenError(f"untrusted subject token issuer {issuer!r}")
        try:
            claims = jwt.decode(
                token,
                trusted.public_key,
                algorithms=["ES256"],
                audience=self.issuer,
                options={
                    "require": ["iss", "sub", "aud", "exp"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(f"subject token rejected: {exc}") from exc
        if int(claims["exp"]) < int(self.clock.now().timestamp()) - _SKEW:
            raise InvalidTokenError("subject token expired")
        return trusted, claims

    def verify_user_token(self, token: str) -> Principal:
        """Authenticate a human (approver, auditor, admin) by an IdP-issued token."""
        try:
            issuer = str(jwt.decode(token, options={"verify_signature": False})["iss"])
        except (jwt.PyJWTError, KeyError) as exc:
            raise InvalidTokenError("malformed user token") from exc
        trusted, claims = self._verify_external(token, issuer)
        if trusted.kind is not IssuerKind.IDP:
            raise InvalidTokenError("user tokens must come from an identity provider")
        principal = self.inventory.find_principal(str(claims["sub"]))
        if principal is None or principal.kind is not PrincipalKind.HUMAN or not principal.active:
            raise InvalidTokenError("subject is not an active human principal")
        return principal

    # -- verification (used by the gateway) -------------------------------------------------

    def verify_access_token(self, token: str, audience: str | None = None) -> AccessClaims:
        options: jwt.types.Options = {
            "require": [
                "iss",
                "sub",
                "aud",
                "exp",
                "iat",
                "jti",
                "scope",
                "act",
                "cnf",
                "session_id",
                "plan_id",
            ],
            "verify_exp": False,
            "verify_iat": False,
            "verify_nbf": False,
            "verify_aud": audience is not None,
        }
        try:
            claims = jwt.decode(
                token,
                self._key.public_key(),
                algorithms=["ES256"],
                audience=audience,
                issuer=self.issuer,
                options=options,
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(str(exc)) from exc
        now = int(self.clock.now().timestamp())
        if int(claims["exp"]) < now - _SKEW:
            raise InvalidTokenError("token expired")
        if int(claims["iat"]) > now + _SKEW:
            raise InvalidTokenError("token issued in the future")
        if int(claims["exp"]) - int(claims["iat"]) > MAX_LIFETIME.total_seconds():
            raise InvalidTokenError("token lifetime exceeds 5 minutes")
        if self.revocations.is_revoked(
            jti=claims["jti"], subject=claims["sub"], iat=int(claims["iat"])
        ):
            raise InvalidTokenError("token revoked")
        chain = act_chain(claims)
        if not chain or len(chain) > MAX_DELEGATION_DEPTH:
            raise InvalidTokenError("invalid delegation chain")
        try:
            root_kind = PrincipalKind(str(claims.get("delegator_kind")))
        except ValueError as exc:
            raise InvalidTokenError("unknown delegator kind") from exc
        if root_kind not in (PrincipalKind.HUMAN, PrincipalKind.TRIGGER):
            raise InvalidTokenError("delegation must end at a human or a trigger")
        jkt = claims["cnf"].get("jkt") if isinstance(claims["cnf"], Mapping) else None
        if not jkt:
            raise InvalidTokenError("token is not sender-constrained")
        return AccessClaims(
            raw=claims,
            subject=str(claims["sub"]),
            audience=str(claims["aud"]),
            scope=frozenset(str(claims["scope"]).split()),
            jti=str(claims["jti"]),
            session_id=str(claims["session_id"]),
            plan_id=str(claims["plan_id"]),
            jkt=str(jkt),
            tenant=str(claims.get("tenant", self.tenant)),
            delegation=Delegation(tuple(chain), root_kind),
            iat=int(claims["iat"]),
            exp=int(claims["exp"]),
        )
