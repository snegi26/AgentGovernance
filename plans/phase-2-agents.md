# Phase 2: Orchestrator and first specialist agents

Source: *Agentic Access Governance — Build Spec* (2026-10-27), Phase 2, as reflected in
`docs/architecture.md` ("Not in this release", "Open questions") and `docs/security-model.md`
("Out of scope for this release"). The spec itself is not in the repository; every item below that
depends on its exact wording is marked **[spec check]** and must be confirmed against it at pickup.

Goal: the first agents land on the 0.1.0 core. An LLM proposes, ranks, drafts and explains; every
verdict still comes from `SodEngine` and Cedar, and every agent action goes through `Gateway.handle`.
Phase 2 ships the agent runtime (model calls, redaction, egress control, evidence of model use), the
orchestrator, the access-request and certification agents, the eval gates and the shadow-run
harness. Phase 3 adds the remaining specialists (provisioner, cert-executor, anomaly monitor) on the
same runtime.

## Why this split

The demo estate already registers contracts for all seven agents. The orchestrator may hand off
only to `access-request` and `certification` (`demo/estate.py: HANDOFFS`), so those three form the
smallest end-to-end slice: one read-only router, one write-with-approval agent and one draft-only
agent. The executors and the anomaly monitor write to target systems or quarantine agents; they
land after the eval and shadow machinery has run on lower-risk agents. **[spec check]** that the
spec's Phase 2 / Phase 3 boundary matches.

## Phases

### Phase A: Close the gaps the agents will depend on
Verified when: an agent whose `eval_status` is not `passed` cannot complete a write, and the
gateway's verdict packages cannot import agent code.
Files to touch: `src/agent_governance/gateway/gateway.py`, `src/agent_governance/identity/registry.py`,
`pyproject.toml`, `tests/gateway/*`, `tests/identity/*`

#### Step A.1: Enforce `eval_status` at the gateway (Size: S)
- Today `eval_status` is stored on the contract but nothing reads it. Shadow and pending agents can
  write.
- Acceptance criteria: `pending` / `failed` ⇒ effective autonomy `read`; `shadow` ⇒ writes are
  evaluated end to end and recorded with `shadow: true`, but never forwarded to the backend;
  `passed` ⇒ contract autonomy. Changing `eval_status` is an owner-approved registry operation and
  writes an evidence record.
- Verification command: `uv run pytest tests/gateway/test_eval_status.py tests/identity/test_registry.py`
- Test seams: `Gateway.handle`, `AgentRegistry`
- Blocked by: none

#### Step A.2: Import boundary between verdict code and agent code (Size: S)
- Acceptance criteria: ruff `TID251` banned-api rules forbid `agent_governance.agents` (and any model
  SDK) from `sod/`, `policy/`, `approval/`, `gateway/` and `evidence/`; a test proves a violating
  import fails lint. Turns CONTRIBUTING ground rule 1 into a check.
- Verification command: `uv run ruff check .`
- Test seams: CI
- Blocked by: none

### Phase B: Agent runtime
Verified when: a scripted agent runs a full plan through the gateway, every model call is redacted,
egress-checked and recorded as evidence, and no model output reaches a tool without passing the
gateway.
Files to touch: `src/agent_governance/agents/{model,redaction,egress,runtime,tools}.py`,
`tests/agents/*`

#### Step B.1: Model client protocol and providers (Size: M)
- Acceptance criteria: `ModelClient` protocol (messages, tool schemas, structured output);
  `ScriptedModel` deterministic fake for tests; one real provider adapter behind an optional
  `[agents]` extra so the core install stays model-free; `model_ref` on the contract selects the
  model, and a call with a different model is refused.
- Verification command: `uv run pytest tests/agents/test_model.py`
- Test seams: `ModelClient`
- Blocked by: A.2

#### Step B.2: PII redaction and egress allow-list (Size: M)
- Acceptance criteria: every prompt passes `Redactor` before leaving the process (emails, names from
  the inventory, personnel numbers, IBANs; reversible tokens so outputs can be re-hydrated locally);
  per-tenant model endpoint and an egress allow-list; a call to an unlisted endpoint fails closed;
  untrusted text reaches the model only via `UntrustedSpan.quoted()`.
- Verification command: `uv run pytest tests/agents/test_redaction.py tests/agents/test_egress.py`
- Test seams: `Redactor`, `ModelClient` wrapper
- Blocked by: B.1

#### Step B.3: Agent loop and evidence of model use (Size: M)
- Acceptance criteria: `AgentRuntime` drives propose → tool call via `AgentClient` → observe, with a
  step budget; tool results come only from the gateway; a new `model.call` evidence kind records
  `model_ref`, prompt and output digests (not raw text), redaction counts and the plan step it
  served; model output that asserts a verdict is passed through unchanged so the gateway's
  `result_ref` check rejects it (test proves the agent cannot bypass it).
- Verification command: `uv run pytest tests/agents/test_runtime.py`
- Test seams: `AgentRuntime.run(plan)`
- Blocked by: B.2

### Phase C: Orchestrator and specialists
Verified when: "Priya needs vendor maintenance in S/4" runs orchestrator → access-request → SoD
simulation → drafted request → approval task, and "review Q4 access for Mark's team" runs
orchestrator → certification → drafted decisions, both with the `ScriptedModel` and both producing
a verifiable evidence packet.
Files to touch: `src/agent_governance/agents/{orchestrator,access_request,certification}.py`,
`src/agent_governance/agents/prompts/*`, `tests/agents/*`, `src/agent_governance/demo/*`

#### Step C.1: Orchestrator (Size: M)
- Acceptance criteria: classifies the request, builds a plan with a `plan_id`, hands off via token
  exchange only to contract-listed agents; holds read tools only; never sees write results it
  didn't route.
- Verification command: `uv run pytest tests/agents/test_orchestrator.py`
- Blocked by: B.3

#### Step C.2: Access-request agent (Size: M)
- Acceptance criteria: ranks candidate roles from `catalog.search_roles`, calls `sod.simulate`, cites
  its `result_ref` in the draft, explains the SoD outcome from the engine's proof path (never its
  own judgment), submits through `iag.submit_request` and stops at `require_approval`. Requests only
  for the delegator or direct reports (already enforced; tested from the agent side).
- Verification command: `uv run pytest tests/agents/test_access_request.py`
- Blocked by: C.1

#### Step C.3: Certification agent (Size: M)
- Acceptance criteria: drafts keep/revoke recommendations from `usage.get` and `sod.static`; autonomy
  `draft` only; every recommendation cites the evidence it used; reviewer rubber-stamp controls:
  canary lines injected into review batches and per-reviewer override-rate tracking, both recorded.
  **[spec check]** canary rate and alert thresholds.
- Verification command: `uv run pytest tests/agents/test_certification.py`
- Blocked by: C.1

### Phase D: Eval gates and shadow run
Verified when: `agent-governance eval run <agent>` scores an agent on a fixed suite and only a
passing run can move it from `shadow` to `passed`; `agent-governance shadow report` compares shadow
decisions with human ones over a period.
Files to touch: `src/agent_governance/evals/*`, `src/agent_governance/cli.py`, `tests/evals/*`,
`evals/suites/*.yaml`

#### Step D.1: Eval harness and gates (Size: M)
- Acceptance criteria: YAML suites per agent (benign, adversarial/injection, SoD-trap cases); hard
  gate "SoD respect = 0" (no submitted request with an unmitigated SoD hit) plus injection-resistance
  and citation-coverage metrics; results written as signed evidence and referenced from the
  contract's `evals`. **[spec check]** the full metric list and thresholds.
- Verification command: `uv run pytest tests/evals`
- Blocked by: C.2, C.3

#### Step D.2: Shadow-run harness (Size: M)
- Acceptance criteria: replays a period of real requests/review items against shadow agents (A.1
  guarantees nothing is forwarded), reports agreement with human decisions, approval-tier
  distribution and deny rates; promotion to `passed` needs the owner and a passing D.1 run.
- Verification command: `uv run pytest tests/evals/test_shadow.py`
- Blocked by: D.1

### Phase E: Demo, docs, release
Verified when: `agent-governance demo` includes both agent journeys with the scripted model and still
passes every 0.1.0 check; docs describe the agent layer; `0.2.0` is tagged.
- Step E.1 (Size: S): extend demo and README; add the agent layer to `docs/architecture.md` and the
  new controls (redaction, egress, rubber-stamp detection, eval gates) to `docs/security-model.md`.
- Step E.2 (Size: S): CHANGELOG `0.2.0`, which also releases the post-0.1.0 review fixes.
- Blocked by: D.2

## Decision log
| Decision | Proposed option | Why | Status |
| --- | --- | --- | --- |
| Phase 2 scope | Orchestrator, access-request, certification + runtime, evals, shadow | Matches the contracts' hand-off graph; writers to target systems wait for the eval machinery | open — confirm against spec |
| Agent framework | Thin in-house loop over a `ModelClient` protocol | Keeps the loop auditable and deterministic under test; LangGraph can wrap it later without changing the gateway contract | open |
| Model provider | Protocol + one adapter in an optional extra | Vendor-neutral core; tests never call a model | open — which provider first |
| Model-call evidence | Digests only, not raw prompts | Evidence must not become a PII store; raw text stays in a separate, retention-limited log if at all | open |
| Self-hosted model option | Supported via the same protocol and egress allow-list | Open question carried from the spec | open |

## Always / Never
- Always: agents act only through `AgentClient` → `Gateway.handle`; every model call is redacted,
  egress-checked and recorded; tests use `ScriptedModel`; adversarial cases for every agent.
- Never: model output as a verdict; agent code imported by verdict packages; real model calls in CI;
  agents writing to target systems before they pass evals (Phase 3 executors included).

## Progress
| Phase | Status |
| --- | --- |
| A Gaps the agents depend on | not started |
| B Agent runtime | not started |
| C Orchestrator and specialists | not started |
| D Eval gates and shadow run | not started |
| E Demo, docs, release | not started |
