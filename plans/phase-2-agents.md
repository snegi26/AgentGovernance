# Phase 2: Orchestrator and first specialist agents

Source: *Agentic Access Governance — Build Spec* (2026-10-27), Phase 2, as reflected in
`docs/architecture.md` ("Not in this release", "Open questions") and `docs/security-model.md`
("Out of scope for this release"). The spec itself is not in the repository; every item below that
depends on its exact wording is marked **[spec check]** and must be confirmed against it at pickup.

Goal: the first agents land on the 0.1.0 core. An LLM proposes, ranks, drafts and explains; every
verdict still comes from `SodEngine` and Cedar, and every agent action goes through `Gateway.handle`.
Phase 2 ships the agent process boundary, a governed model proxy (redaction, egress control,
evidence of model use), eval suites, the orchestrator, the access-request and certification agents,
and the shadow-run harness. Phase 3 adds the remaining specialists (provisioner, cert-executor,
anomaly monitor) on the same runtime. `ap-automation` stays a demo contract for SoD abuse cases,
not a product agent.

## Why this split

The demo estate already registers contracts for all seven agents. The orchestrator may hand off
only to `access-request` and `certification` (`demo/estate.py: HANDOFFS`), so those three form the
smallest end-to-end slice: one read-only router, one write-with-approval agent and one draft-only
agent. The executors and the anomaly monitor write to target systems or quarantine agents; they
land after the eval and shadow machinery has run on lower-risk agents. **[spec check]** that the
spec's Phase 2 / Phase 3 boundary matches.

## Constraints found in the 0.1.0 code

These shape the phase order below.

1. **Agents must not share a process with `Runtime`.** `AgentClient` holds the whole `Runtime`,
   which holds `Keys.approval_signing`. Any agent loop built on `AgentClient` can reach the approval
   key, which `docs/security-model.md` says must stay out of reach of agent processes. Phase 2 agents
   therefore talk to the gateway only over HTTP (`/token`, `/mcp/{server}`), with nothing but their
   own key.
2. **Controls placed in agent code are advisory.** If redaction, the egress allow-list and model-call
   evidence live in the agent process, a compromised or injected agent can skip them. They belong
   in a model proxy behind the gateway, where the agent cannot route around them.
3. **`eval_status` is stored but never enforced**, and the demo registers every agent as `shadow`
   while expecting their writes to go through. Enforcing it changes the demo's expected verdicts.
4. **Shadow writes must not touch shared state.** If shadow calls open approval tasks or are
   recorded as executed SoD steps, they would page real approvers and cause false session-SoD
   denials for live agents.

## Phases

### Phase A: Gaps the agents depend on
Verified when: an agent whose `eval_status` is not `passed` cannot complete a write, shadow calls
leave no trace outside their own evidence records, and verdict packages cannot import agent code.
Files to touch: `src/agent_governance/gateway/gateway.py`, `src/agent_governance/identity/registry.py`,
`src/agent_governance/approval/service.py`, `src/agent_governance/demo/*`, `pyproject.toml`,
`tests/gateway/*`, `tests/identity/*`

#### Step A.1: Enforce `eval_status` at the gateway (Size: M)
- Acceptance criteria:
  - `pending` / `failed` ⇒ effective autonomy `read`.
  - `shadow` ⇒ writes run the full pipeline and are recorded as `gateway.decision` with
    `shadow: true`, then are never forwarded. They open no approval task, notify no one, and are
    not recorded as executed SoD steps.
  - `passed` ⇒ contract autonomy.
  - Changing `eval_status` needs the owner, writes an evidence record, and moving to `passed` must
    cite a passing eval run (enforced once D.1 exists; until then only the owner is required).
  - Demo contracts that need to write move to `passed`; the demo gains a check showing a `shadow`
    agent's write is evaluated but not executed. All existing 20 checks still pass.
- Verification command: `uv run pytest tests/gateway/test_eval_status.py tests/identity/test_registry.py && uv run agent-governance demo`
- Test seams: `Gateway.handle`, `AgentRegistry`
- Blocked by: none

#### Step A.2: Import boundary between verdict code and agent code (Size: S)
- Acceptance criteria: an `import-linter` forbidden contract (also catches transitive imports, which
  ruff's banned-api does not) stops `sod`, `policy`, `approval`, `gateway` and `evidence` from
  importing `agent_governance.agents` or any model SDK; CI runs it. Turns CONTRIBUTING ground rule 1
  into a check.
- Verification command: `uv run lint-imports`
- Test seams: CI
- Blocked by: none

### Phase B: Agent boundary and governed model proxy
Verified when: a scripted agent in a separate process runs a full plan through the HTTP gateway
holding only its own key, and every model call it makes is redacted, egress-checked and recorded by
the proxy, not by the agent.
Files to touch: `src/agent_governance/agents/{client,runtime}.py`,
`src/agent_governance/modelproxy/{proxy,redaction,egress,providers}.py`,
`src/agent_governance/gateway/http.py`, `tests/agents/*`, `tests/modelproxy/*`

#### Step B.1: HTTP agent client (Size: S)
- Acceptance criteria: `RemoteAgentClient` does token exchange and `tools/call` over HTTP with DPoP,
  constructed from the gateway URL and the agent's private key only; a test proves it cannot reach
  `Runtime` or any service key. The in-process `AgentClient` stays for tests and the demo.
- Verification command: `uv run pytest tests/agents/test_client.py`
- Test seams: FastAPI test client
- Blocked by: none

#### Step B.2: Model proxy with provider protocol (Size: M)
- Acceptance criteria:
  - The proxy is a gateway endpoint (`/model/{agent}`) authorised with the agent's DPoP-bound
    token; the model is selected from the contract's `model_ref`, never from the request.
  - `ModelProvider` protocol, with `ScriptedProvider` (deterministic fake) for tests and one real
    adapter behind an optional `[agents]` extra, so the core install stays model-free.
  - Fail closed: a provider outage returns an error the agent must surface to a human queue; it
    never silently retries elsewhere.
  - Per-plan token and step budgets, enforced at the proxy.
- Verification command: `uv run pytest tests/modelproxy/test_proxy.py`
- Test seams: proxy endpoint
- Blocked by: A.2, B.1

#### Step B.3: Redaction and egress allow-list at the proxy (Size: M)
- Acceptance criteria: every prompt passes `Redactor` in the proxy (emails, inventory names,
  personnel numbers, IBANs) with reversible tokens kept in the proxy, so outputs are re-hydrated
  there; per-tenant model endpoints and an egress allow-list, failing closed on an unlisted
  endpoint; untrusted fields reach the model only as `UntrustedSpan.quoted()` JSON data.
- Verification command: `uv run pytest tests/modelproxy/test_redaction.py tests/modelproxy/test_egress.py`
- Test seams: proxy endpoint
- Blocked by: B.2

#### Step B.4: Agent loop, prompt pinning and model-call evidence (Size: M)
- Acceptance criteria:
  - `AgentRuntime` drives propose → tool call → observe through `RemoteAgentClient` and the proxy,
    with a step budget.
  - Prompts are versioned files whose content digest is part of the agent contract, like
    `ruleset_version`; a prompt or `model_ref` change is a new agent version and resets
    `eval_status` to `pending`.
  - The proxy writes a `model.call` evidence record: `model_ref`, prompt digest, prompt and output
    digests (not raw text), redaction counts and the `plan_id`.
  - Model output that asserts a verdict reaches the gateway unchanged, and a test shows the
    `result_ref` check rejects it.
- Verification command: `uv run pytest tests/agents/test_runtime.py`
- Test seams: `AgentRuntime.run(plan)`
- Blocked by: B.3

### Phase C: Eval suites (written before the agents)
Verified when: `agent-governance eval run <agent>` scores an agent against a fixed suite and the
suites for the three Phase 2 agents exist and fail against a stub agent.
Files to touch: `src/agent_governance/evals/*`, `src/agent_governance/cli.py`, `tests/evals/*`,
`evals/suites/*.yaml`

#### Step C.1: Eval harness and gates (Size: M)
- Acceptance criteria: YAML suites per agent (benign, injection, SoD-trap and out-of-scope cases),
  with expected outcomes worked out by hand or from the engine, never from a model run. Hard gate
  "SoD respect = 0" (no submitted request with an unmitigated SoD hit), plus injection resistance
  and citation coverage. Results are written as signed evidence and referenced from the contract's
  `evals`. CI runs suites against `ScriptedProvider`; live-model runs are opt-in and never in CI.
  **[spec check]** the full metric list and thresholds.
- Verification command: `uv run pytest tests/evals`
- Blocked by: B.4

### Phase D: Orchestrator and specialists
Verified when: each agent passes its C.1 suite against a live model (opt-in run, recorded as
evidence), and the demo journeys "Priya needs vendor maintenance in S/4" and "review Q4 access for
Mark's team" run end to end with `ScriptedProvider` and produce a verifiable evidence packet.
Files to touch: `src/agent_governance/agents/{orchestrator,access_request,certification}.py`,
`src/agent_governance/agents/prompts/*`, `tests/agents/*`, `src/agent_governance/demo/*`

#### Step D.1: Orchestrator (Size: M)
- Acceptance criteria: classifies the request, builds a plan with a `plan_id`, hands off via token
  exchange only to contract-listed agents; holds read tools only; never sees write results it
  didn't route.
- Verification command: `uv run pytest tests/agents/test_orchestrator.py`
- Blocked by: C.1

#### Step D.2: Access-request agent (Size: M)
- Acceptance criteria: ranks candidate roles from `catalog.search_roles`, calls `sod.simulate`,
  cites its `result_ref` in the draft and submits through `iag.submit_request`, stopping at
  `require_approval`. The approval task shows the approver the engine's proof path as the
  authority; the model's explanation is shown separately and labelled as model-generated.
- Verification command: `uv run pytest tests/agents/test_access_request.py`
- Blocked by: D.1

#### Step D.3: Certification agent (Size: M)
- Acceptance criteria: drafts keep/revoke recommendations from `usage.get` and `sod.static`; autonomy
  `draft` only; every recommendation cites the evidence it used.
- Verification command: `uv run pytest tests/agents/test_certification.py`
- Blocked by: D.1

#### Step D.4: Reviewer rubber-stamp detection (Size: M)
- Acceptance criteria: canary items injected into review batches are marked in evidence and can
  never be executed (the gateway denies `review.revoke` on a canary); per-reviewer override-rate
  and canary-miss tracking, both recorded. **[spec check]** canary rate and alert thresholds.
- Verification command: `uv run pytest tests/agents/test_rubber_stamp.py`
- Blocked by: D.3

### Phase E: Shadow run
Verified when: `agent-governance shadow report` compares shadow decisions with human ones over a
period, and only an owner holding a passing C.1 run can promote an agent to `passed`.
Files to touch: `src/agent_governance/evals/shadow.py`, `src/agent_governance/cli.py`, `tests/evals/*`

#### Step E.1: Shadow-run harness (Size: M)
- Acceptance criteria: replays a recorded request/review stream against shadow agents (A.1
  guarantees nothing is forwarded); reports agreement with human decisions, approval-tier
  distribution and deny rate. The input is a recorded-traffic file format with a synthetic fixture
  for tests; capturing live traffic is a deployment concern and not part of this step.
- Verification command: `uv run pytest tests/evals/test_shadow.py`
- Blocked by: D.2, D.3

### Phase F: Demo, docs, release
Verified when: `agent-governance demo` includes both agent journeys with `ScriptedProvider` and
still passes every 0.1.0 check; docs describe the agent layer; `0.2.0` is tagged.
- Step F.1 (Size: S): extend demo and README; add the agent boundary and model proxy to
  `docs/architecture.md`, and the new controls (redaction, egress, prompt pinning, rubber-stamp
  detection, eval gates) to `docs/security-model.md`.
- Step F.2 (Size: S): CHANGELOG `0.2.0`.
- Blocked by: E.1

## Before Phase A

Cut `0.1.1` from the current branch with the post-0.1.0 review fixes already under *Unreleased*.
They are security fixes and should not wait for the agents.

## Decision log
| Decision | Proposed option | Why | Status |
| --- | --- | --- | --- |
| Phase 2 scope | Orchestrator, access-request, certification + boundary, proxy, evals, shadow | Matches the contracts' hand-off graph; writers to target systems wait for the eval machinery | open — confirm against spec |
| Agent process boundary | HTTP only; agents hold their own key and nothing else | `AgentClient` exposes `Runtime` and the approval key | proposed |
| Where model controls live | Model proxy behind the gateway | Controls in agent code can be skipped by the agent they constrain | proposed |
| Eval order | Suites before agents | Expected outcomes come from the spec and the engine, not from what a built agent happens to do | proposed |
| Agent framework | Thin in-house loop over the proxy | Keeps the loop auditable and deterministic under test; LangGraph can wrap it later without changing the boundary | open — needed before B.4 |
| Model provider | Protocol + one adapter in an optional extra | Vendor-neutral core; CI never calls a model | open — which provider first, needed before B.2 |
| Model-call evidence | Digests only, not raw prompts | Evidence must not become a PII store; raw text, if kept, goes to a separate retention-limited log | open |
| Self-hosted model option | Supported through the same provider protocol and egress allow-list | Open question carried from the spec | open |

## Always / Never
- Always: agents act only over HTTP through the gateway with their own key; every model call goes
  through the proxy; tests use `ScriptedProvider`; every agent has adversarial eval cases written
  before it is built.
- Never: model output as a verdict; agent code in a process that holds service keys; agent code
  imported by verdict packages; real model calls in CI; shadow calls that open approvals or
  count as executed steps; agents writing to target systems before they pass evals.

## Progress
| Phase | Status |
| --- | --- |
| A Gaps the agents depend on | not started |
| B Agent boundary and model proxy | not started |
| C Eval suites | not started |
| D Orchestrator and specialists | not started |
| E Shadow run | not started |
| F Demo, docs, release | not started |
