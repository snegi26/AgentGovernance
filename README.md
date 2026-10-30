# Agent Governance

Vendor-neutral access governance for **human, non-human and AI-agent identities**, built on one rule: *an LLM may propose, rank, draft and explain, but it never returns a compliance verdict.* Verdicts come from a deterministic SoD engine and a Cedar policy engine. Every decision is written to a tamper-evident evidence log before anything happens.

This release (`0.1.0`) implements the **deterministic core and the enforcement gateway**, which are Phases 0 and 1 of the [build spec](docs/architecture.md#scope-of-this-release). The agents (Phase 2+) are meant to land on a core that can already veto them.

```
agent ──DPoP token──▶ gateway ──▶ token ✓ → scope ✓ → contract ✓ → delegator ✓
                         │        → SoD (session + simulation) → approval tier
                         │        → Cedar → evidence record ──▶ tool server
                         └──▶ deny / require_approval (signed, payload-bound)
```

## What it guarantees

| Guarantee | How |
| --- | --- |
| No ambient agent authority | Agents act only through RFC 8693 delegated tokens whose `act` chain ends at a human or a registered trigger. Effective permission is the agent contract ∩ the delegator. |
| Per-hop authorization | Every tool call is re-evaluated with the accumulated session, so a chain of individually permitted steps can still be denied. |
| Session-level SoD | Creating vendor V and then posting an invoice to V in one plan, or within 24 hours for the same delegator, is denied, and splitting the work across sessions doesn't help. |
| Humans commit high-risk writes | Approvals are Ed25519-signed over the exact call hash, expire, need distinct named approvers per tier and reject self-approval. |
| Stolen tokens are useless | Tokens live 5 minutes, are audience-bound to one tool server and DPoP-bound (RFC 9449) to the agent's key. |
| Evidence by default | Each decision is appended to a per-tenant daily hash chain. Daily roots are anchored and auditor packets verify offline. |
| Fail closed | If the policy engine, SoD engine or evidence store is down, writes are denied and reads come from cache with `stale: true`. |

All four abuse cases the spec requires before GA are tests (`tests/gateway/test_abuse_cases.py`) and demo steps.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/snegi26/AgentGovernance && cd AgentGovernance
uv sync                      # or: python -m venv .venv && pip install -e .
uv run agent-governance demo --packet-dir out/
```

The demo wires a synthetic estate (fictional ACME: SAP S/4HANA and Entra ID exports loaded through the real connectors) and checks 21 expected-versus-actual verdicts. It exits non-zero if any guarantee fails:

```
4. Abuse cases the spec requires to be denied
  [PASS] Injected justification ('grant SAP_ALL')
         expected require_approval, got require_approval - no grant; tier=high_risk_write; flags=possible_injection,privileged_profile_reference
  [PASS] Same plan posts an invoice to V-90017
         expected deny, got deny - denied by SoD: P2P-01
  [PASS] Token replayed from another host
         expected deny, got deny - DPoP check failed: DPoP key does not match the token's cnf.jkt
...
21/21 checks passed
```

### Other commands

```bash
agent-governance rules validate my-rules.yaml                       # version, digest, counts
agent-governance sod static   --principal user:sam@acme --sap s4.json --entra graph.json
agent-governance sod simulate --principal user:priya@acme --add Z_VENDOR_MAINT
agent-governance evidence verify-packet out/AC-SOD-01.json --signer-key=<b64> --tsa-key=<b64>   # "=" form: base64url keys can start with "-"
agent-governance serve        # dev-only HTTP gateway over the demo estate (needs the [server] extra)
```

## Using it as a library

```python
from agent_governance.demo.estate import build_demo

estate = build_demo()                     # or build a Runtime over your own Inventory
agent = estate.agent("ap-automation")
token = agent.exchange(estate.user_token("user:priya@acme"), "s4", plan_id="plan-1")

result = agent.call(token, "s4.vendor_create", {"vendor_id": "V-1"})
result.verdict            # Verdict.REQUIRE_APPROVAL, because the agent's autonomy is write_with_approval
approval = estate.runtime.approvals.approve(result.approval_task_id, "user:mark@acme", "line_manager")
agent.call(token, "s4.vendor_create", {"vendor_id": "V-1"}, approvals=[approval]).verdict   # ALLOW
agent.call(token, "s4.invoice_post", {"vendor_id": "V-1"}).verdict                          # DENY (P2P-01)
```

`Runtime` (`agent_governance.runtime`) is the composition root. Swap in your own `Inventory` (filled by connectors), `Ruleset`, Cedar policy file, `ToolBackend` and `TimestampAuthority`.

## HTTP API

`agent_governance.gateway.http.create_app(runtime)` returns a FastAPI app:

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /token` | DPoP proof + agent assertion + subject token | RFC 8693 token exchange |
| `POST /mcp/{server}` | `Authorization: DPoP …` + `DPoP` proof | MCP JSON-RPC: `initialize`, `tools/list`, `tools/call` (approvals in `_meta.approvals`) |
| `GET /approvals`, `POST /approvals/{id}/approve\|reject` | IdP bearer | Approver inbox and decisions |
| `POST /sod/static`, `POST /sod/simulate` | IdP bearer | SoD checks with proof paths |
| `GET /evidence/verify`, `POST /evidence/packets` | IdP bearer + `audit.read_evidence` | Chain verification and auditor packets |
| `GET /.well-known/jwks.json`, `GET /healthz` | none | Discovery |

## Rule sets

SoD rules are versioned YAML: actions with their technical permissions, business functions, risks (pairs or single critical functions) with per-risk `join_keys` for session relatedness, and optional mitigations. The bundled starter library, `src/agent_governance/rules/starter/sap_s4.yaml`, covers P2P, O2C, R2R, Basis and Entra critical roles. **It is a starting point, not a certified rule set.** Review it against your landscape. Every verdict records the `ruleset_version` and a content digest.

## Project layout

```
src/agent_governance/
  sod/          Datalog evaluator, rule sets, static/simulation/session checks
  identity/     principals, agent registry, token exchange, DPoP, revocation
  policy/       tool catalogue, Cedar engine, default policies
  approval/     tiers and the signed-approval service
  gateway/      enforcement pipeline, MCP/HTTP surface, untrusted-text handling
  evidence/     hash-chained store, anchoring, auditor packets
  connectors/   SAP S/4HANA and Microsoft Entra ID (read-only)
  demo/         synthetic estate and the end-to-end walkthrough
```

## Documentation

- [Architecture and spec mapping](docs/architecture.md): layers, the per-call pipeline, and every deliberate deviation from the spec
- [Security model](docs/security-model.md): threat-by-threat controls and what is out of scope
- [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md), [Changelog](CHANGELOG.md)

## Status

Alpha. The deterministic core and gateway are complete and tested (95% coverage, ruff, mypy strict). The production adapters are interfaces with reference implementations: Postgres, Iceberg/S3 Object Lock, an RFC 3161 TSA, live SAP/Entra connectors, and Envoy. See [what is not in this release](docs/architecture.md#not-in-this-release).

## License

[Apache License 2.0](LICENSE). SAP, S/4HANA, Microsoft Entra ID, Okta and AWS are trademarks of their respective owners. This project is not affiliated with or endorsed by them.
