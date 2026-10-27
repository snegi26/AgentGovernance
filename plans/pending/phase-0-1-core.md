# Phase 0+1: Deterministic core and policy gateway

Source: *Agentic Access Governance — Build Spec* (2026-10-27), sections "Identity and delegation",
"Policy enforcement gateway", "SoD engine", "Data model and evidence store", "Security".

Goal: a Python package `agent-governance` (import `agent_governance`) that ships the parts of the system that own verdicts — the SoD
engine, the policy gateway with delegated identity, the approval service and the evidence store — so
that agents (Phase 2+) land on a core that can already veto them.

## Phases

### Phase A: Repo skeleton and toolchain
Verified when: `uv run ruff check && uv run mypy && uv run pytest` passes on an empty test suite in CI.
Files to touch: `pyproject.toml`, `src/agent_governance/__init__.py`, `.github/workflows/ci.yml`, `LICENSE`,
`README.md`, `.gitignore`

#### Step A.1: Package skeleton (Size: S)
- Acceptance criteria: `uv sync` installs; ruff, mypy (strict) and pytest run green; CI runs on
  Python 3.11–3.13.
- Verification command: `uv run ruff check . && uv run mypy && uv run pytest`
- Test seams: CI
- Blocked by: none

### Phase B: SoD engine (Phase 0 of spec)
Verified when: static, simulation and session checks return violations with derivation paths on the
starter rule library; the vendor-create → invoice-post session case is denied.
Files to touch: `src/agent_governance/sod/{datalog,ruleset,engine,session}.py`,
`src/agent_governance/rules/starter/*.yaml`, `tests/sod/*`

#### Step B.1: Embedded Datalog evaluator with proof paths (Size: M)
- Acceptance criteria: semi-naive bottom-up evaluation of positive Horn rules with stratified negation;
  every derived fact keeps one derivation (rule + premises); recursion supported.
- Verification command: `uv run pytest tests/sod/test_datalog.py`
- Test seams: `Program.evaluate()` / `Program.explain(fact)`
- Blocked by: A.1

#### Step B.2: Rule model, versioned rulesets and starter library (Size: M)
- Acceptance criteria: YAML ruleset loads into `risk`, `function_action`, `action_permission`,
  `mitigation` and `relation` (join keys) facts; `ruleset_version` is mandatory and content-hashed;
  starter library covers SAP P2P/O2C/GL/Basis risks and critical single functions.
- Verification command: `uv run pytest tests/sod/test_ruleset.py`
- Test seams: `Ruleset.load(path)`
- Blocked by: B.1

#### Step B.3: Static and simulation checks (Size: M)
- Acceptance criteria: `static(principal)` returns violations with proof path
  risk → functions → actions → roles; `simulate(principal, add=[..], remove=[..])` returns added and
  removed violations; mitigations with a valid `valid_to` mark a violation mitigated, not absent.
- Verification command: `uv run pytest tests/sod/test_static.py tests/sod/test_simulate.py`
- Test seams: `SodEngine`
- Blocked by: B.2

#### Step B.4: Session-level SoD (Size: M)
- Acceptance criteria: `session_check(session_id, proposed)` returns allow / deny / require_approval;
  relatedness via per-risk join keys (vendor_id, company_code); scope is `plan_id` **and** a 24-hour
  rolling window per delegating principal, so splitting across sessions doesn't evade it; p95 < 150 ms
  on a 10k-action window.
- Verification command: `uv run pytest tests/sod/test_session.py`
- Test seams: `SodEngine.session_check`
- Blocked by: B.3

### Phase C: Evidence store
Verified when: records are hash-chained per tenant per day, tampering with any record is detected by
`verify()`, daily roots are anchored, and a packet for a control and a period verifies offline.
Files to touch: `src/agent_governance/evidence/{record,store,anchor,packet}.py`, `tests/evidence/*`

#### Step C.1: Hash-chained, append-only store (Size: M)
- Acceptance criteria: canonical JSON (RFC 8785-style) hashing; `prev_hash` chain per (tenant, day);
  SQLite backend with UPDATE/DELETE blocked by triggers; `verify(tenant, day)` finds the first bad link.
- Verification command: `uv run pytest tests/evidence/test_store.py`
- Test seams: `EvidenceStore`
- Blocked by: A.1

#### Step C.2: Daily root anchoring and evidence packets (Size: M)
- Acceptance criteria: `Anchor` protocol with a local Ed25519 timestamp signer (RFC 3161 client is the
  production adapter, stubbed behind the protocol); packet = JSON bundle of records + ruleset versions
  + approvals + chain proofs, signed; `agent-governance evidence verify-packet` validates it offline.
- Verification command: `uv run pytest tests/evidence/test_packet.py`
- Test seams: `PacketBuilder`, CLI
- Blocked by: C.1

### Phase D: Identity and delegation (Phase 1 of spec)
Verified when: tokens minted by token exchange carry nested `act`, are ≤ 5 min, audience-bound,
DPoP-bound, and the gateway rejects replay from another key.
Files to touch: `src/agent_governance/identity/{principals,registry,sts,dpop,revocation}.py`, `tests/identity/*`

#### Step D.1: Principal model and agent registry (Size: S)
- Acceptance criteria: human / nhi / agent / trigger principals; NHI and trigger require a human owner;
  registry holds the spec's fields; triggers carry an owner-approved policy envelope.
- Verification command: `uv run pytest tests/identity/test_registry.py`
- Test seams: `AgentRegistry`
- Blocked by: A.1

#### Step D.2: Token exchange (RFC 8693) and DPoP (RFC 9449) (Size: M)
- Acceptance criteria: STS issues ES256 JWTs with `sub=agent`, nested `act` (depth ≤ 3), `scope` = tool
  IDs ∩ contract, `aud` = one tool server, `cnf.jkt` = agent key thumbprint, `session_id`, `plan_id`;
  autonomous (no OBO/trigger delegator) is refused; DPoP proof verification checks `htm`, `htu`, `iat`,
  `jti` replay, `ath`, and key thumbprint.
- Verification command: `uv run pytest tests/identity`
- Test seams: `TokenService.exchange`, `DpopVerifier.verify`
- Blocked by: D.1

### Phase E: Policy, approvals and the gateway
Verified when: the four abuse cases in the spec are denied end to end through the gateway, and gateway
decision p95 < 50 ms / p99 < 150 ms excluding tool time.
Files to touch: `src/agent_governance/policy/*`, `src/agent_governance/approval/*`, `src/agent_governance/gateway/*`,
`tests/gateway/*`, `tests/abuse/*`

#### Step E.1: Cedar policy engine and default policy set (Size: M)
- Acceptance criteria: Cedar schema for Agent / Delegator / Tool / Resource; default policies from the
  spec (submit-request permit, grant-group forbid unless approval hash matches); action classes
  (read / draft / low-risk write / high-risk write / bulk revoke) drive approval tiers.
- Verification command: `uv run pytest tests/policy`
- Test seams: `PolicyEngine.decide`
- Blocked by: D.2

#### Step E.2: Approval service (Size: S)
- Acceptance criteria: approvals are Ed25519-signed over `call_hash`, approver, tier and expiry; required
  approver roles per tier; an expired approval or one for a different payload is rejected.
- Verification command: `uv run pytest tests/approval`
- Test seams: `ApprovalService`
- Blocked by: E.1

#### Step E.3: Gateway pipeline (Size: M)
- Acceptance criteria: the spec's six per-call steps in order; evidence written **before** forwarding;
  fail closed — engine/evidence unavailable ⇒ writes denied, reads served from cache with a
  `stale: true` flag; untrusted text fields are scanned and flagged in the evidence record, never
  interpreted.
- Verification command: `uv run pytest tests/gateway tests/abuse`
- Test seams: `Gateway.handle(call)`
- Blocked by: B.4, C.1, E.2

#### Step E.4: HTTP surface (Size: S)
- Acceptance criteria: FastAPI app exposing MCP-style JSON-RPC `tools/call` through the gateway, plus
  `/token` (exchange), `/approvals`, `/sod/{static,simulate}` and `/healthz`; OpenAPI published.
- Verification command: `uv run pytest tests/http`
- Test seams: `fastapi.testclient`
- Blocked by: E.3

### Phase F: Connectors, demo and docs
Verified when: `uv run agent-governance demo` runs every abuse case and the happy path, printing verdicts and a
verified evidence packet; docs build from the repo.

#### Step F.1: Read-only connector interface + fixture connectors (Size: S)
- Acceptance criteria: `Connector` protocol (`principals()`, `assignments()`, `roles()`); fixture
  adapters shaped like SAP S/4HANA (AGR_USERS / AGR_1251) and Entra ID (users / groups / appRoleAssignments).
- Blocked by: B.2

#### Step F.2: Demo and repo hygiene (Size: M)
- Acceptance criteria: `agent-governance demo` scenario; README, ARCHITECTURE.md, SECURITY.md (threat model),
  CONTRIBUTING.md, CODE_OF_CONDUCT.md, CHANGELOG.md; Apache-2.0 headers via SPDX lines.
- Blocked by: E.4, C.2, F.1

## Decision log
| Decision | Chosen option | Why |
| --- | --- | --- |
| Scope | Spec Phase 0 + Phase 1 | Spec: "agents land only after the engine can veto them" |
| Language | Python ≥ 3.11, uv, ruff, mypy strict, pytest | User choice; best fit for later LangGraph agents |
| Policy engine | Cedar via `cedarpy` (official Rust engine bindings) | Spec names Cedar; probe confirmed it runs in-process |
| SoD engine | Embedded Python Datalog evaluator with derivation tracking | Soufflé is a C++ toolchain; spec allows an embedded equivalent, and proof paths are first-class |
| Tokens | Self-contained STS (ES256 JWT, RFC 8693 shape) | IdP is out of scope to replace; this is the exchange endpoint Keycloak/Entra would front |
| Storage | Repository protocols, SQLite reference backend | Runs anywhere for tests and demo; Postgres adapter is a follow-up |
| License | Apache-2.0, starter rules authored here under the same license | User choice; avoids third-party rule library licensing |

## Not yet specified
- Postgres backend and Iceberg/S3 Object Lock mirror: protocols ship now, adapters later.
- Real RFC 3161 TSA client: protocol ships, local signer is the reference.
- Live SAP RFC/OData and Entra Graph connectors: need credentials and test tenants.
- Spec open questions (triggered-agent per-event acknowledgement, join-key maintenance on customer
  rule extensions, framework mapping order) stay open; defaults are documented in ARCHITECTURE.md.
- Phase 2+ (agents, orchestrator, anomaly monitor, Z3 proofs): fog, researched at pickup.

## Always / Never
- Always: deterministic verdicts; every decision writes an evidence record before the action proceeds;
  fail closed on writes; tests for each spec abuse case.
- Never (this plan): LLM calls, agents, orchestrator, UI, Okta/AWS connectors, Z3, publishing to PyPI.

## Progress
| Phase | Status |
| --- | --- |
| A | pending |
| B | pending |
| C | pending |
| D | pending |
| E | pending |
| F | pending |
