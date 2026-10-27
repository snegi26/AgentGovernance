# Security model

The main threat is injected text steering an agent toward a write. The defence is that **no agent can complete a write on its own say-so**. Content scanning only raises the bar and leaves a trail.

## Threats and controls

| Threat | Vector | Control in this release | Test |
| --- | --- | --- | --- |
| Prompt injection | Justifications, firefighter reasons, log lines, alert payloads | Untrusted fields are declared per tool and scanned (NFKC-folded, zero-width stripped). A hit raises the tier to high-risk and is recorded as a flag on the decision. No write tool runs without an engine verdict and, where tiered, a human approval. `UntrustedSpan.quoted()` passes text to models as JSON data with provenance. | `test_abuse_cases.py::test_injected_justification…`, `test_untrusted.py` |
| Privilege laundering | Permitted steps chained into a toxic pair | Session SoD on every write. Scope is the plan plus a 24 h rolling window per delegator. Missing join keys count as related. | `test_session.py`, `test_abuse_cases.py::test_split_plan…` |
| Confused deputy | Agent uses its own authority | No ambient authority: Cedar permits only when the agent contract, token scope *and* delegator entitlement all agree. Exchange without a subject token is refused. Hand-offs are allowed only to agents the delegating contract names in `may_delegate_to`, and triggers start only their listed agents. | `test_policy_engine.py::test_no_permit_means_deny`, `test_sts.py::test_no_subject_token…` |
| Token theft or replay | Leaked bearer token | DPoP (`cnf.jkt`, `ath`, `htm`/`htu`, `jti` replay cache), 5-minute lifetime, audience bound to one tool server, revocation list by `jti` and by subject. | `test_dpop.py`, `test_abuse_cases.py::test_token_replayed…` |
| Approval spoofing | Approval reused for another payload, or replayed | Approvals sign `call_hash` (tool, arguments, agent, delegator, plan, audience), expire, and are **spent** once the call they authorize is allowed. The approver must still hold the role at verification time. No self-approval, and one person cannot fill two roles. A rejection is final for that exact payload. Only holders of a required role (never the delegator) can reject. | `test_approval_service.py`, `test_approval_lifecycle.py`, `test_abuse_cases.py::test_approval_for_a_different_payload…` |
| Request on behalf of others | Agent targets an arbitrary user | `request_access_self_or_reports` is enforced literally: the target must be the delegator or one of their direct reports. | `test_approval_lifecycle.py::test_requests_only_for_self_or_direct_reports` |
| Verdict forgery by a model | Agent output claims `compliant: true` | Non-read calls whose arguments assert a verdict must cite an existing `sod.verdict` evidence record. | `test_gateway.py::test_verdict_claims…` |
| Agent compromise | Behaviour drift, deny-rate spike | Quarantine sets autonomy to `read` and revokes every token issued so far. Only the agent's owner can restore it. | `test_gateway.py::test_quarantine…`, `test_registry.py` |
| Evidence tampering | Admin edits records | Append-only triggers, per-day hash chain, and anchored daily roots whose signed token is re-checked on every verification. Signed packets are verified with keys from the auditor's trust store, never from the packet. | `test_store.py`, `test_packet.py` |
| Dependency outage | Policy, SoD or evidence store down | Fail closed: writes denied, reads only from cache with `stale: true`. Any unexpected error in the pipeline becomes a recorded deny. | `test_gateway.py::test_*_fails_closed`, `…evidence_outage…` |

## Trust boundaries and assumptions

- **Keys.** `runtime.Keys` generates ephemeral keys by default. Production must load the token-signing, approval-signing, packet-signing and TSA keys from a KMS or HSM, and must keep the approval key out of reach of agent processes.
- **Clock.** Every expiry check uses the injected `Clock`. Production uses `SystemClock` on NTP-synchronised hosts. A 5-second skew is tolerated.
- **DPoP replay cache.** The cache is per process. Behind several gateway replicas, share it (for example in Redis), or a proof could be replayed against a different replica within its 60-second window.
- **Public URLs.** DPoP `htu` is checked against `Settings.base_url`, never the `Host` header. Terminate TLS in front of the gateway and configure the public URL exactly.
- **Approver identity.** Approver and auditor endpoints trust the configured IdP. Approvals are only as strong as the IdP's authentication of approvers, so enforce phishing-resistant MFA there.
- **Untrusted-text scanning is heuristic.** It is not a security boundary. The approval requirement is.

## Out of scope for this release

PII redaction before model calls, egress allow-lists, per-tenant model endpoints, and reviewer rubber-stamp detection (canary lines, override-rate tracking) arrive with the agents in Phase 2+.
