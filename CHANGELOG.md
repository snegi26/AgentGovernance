# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Approvals are single-use: they are spent when the call they authorize is allowed.
- A rejection is final for its exact payload. Resubmitting no longer opens a fresh task.
- Only holders of a required approver role, and never the delegator, can reject or view a task.
- `request_access_self_or_reports` is enforced: requests may target only the delegator or their direct reports.
- Hand-offs require the receiving agent in the delegating contract's `may_delegate_to`. A trigger's `agents` allowlist is enforced.
- Evidence verification re-checks anchor tokens, not just the stored root.
- A failed evidence append always rolls back its transaction. Float arguments no longer crash the gateway, and unexpected errors become recorded denies.
- LINE_MANAGER approvals for triggered work resolve to the trigger's owner.

## [0.1.0] - 2026-10-27

First release: the deterministic core and the enforcement gateway (spec Phases 0 and 1).

### Added

- Embedded Datalog evaluator with stratified negation and per-fact derivations (proof paths).
- Versioned, content-hashed SoD rule sets and a starter library for SAP S/4HANA and Microsoft Entra ID.
- Static, what-if simulation and session-level SoD checks. Session scope spans the plan and a 24-hour window per delegator.
- Append-only, hash-chained evidence store with daily anchoring and signed auditor packets that verify offline.
- Agent registry with contracts, quarantine and owner-approved restore, and trigger registrations with owner-approved envelopes.
- RFC 8693 token exchange issuing 5-minute, audience-bound, DPoP-bound (RFC 9449) tokens with nested `act` claims.
- Cedar policy engine and default policy set. The gateway runs the per-call pipeline and fails closed.
- Signed, expiring, payload-bound approvals with tiered approver roles.
- Untrusted-text flagging and enforcement of engine `result_ref` citations.
- Read connectors for SAP S/4HANA table exports and Microsoft Graph shapes.
- FastAPI surface: `/token`, MCP JSON-RPC per tool server, approvals, SoD and evidence APIs.
- `agent-governance` CLI with an end-to-end demo covering the spec's four abuse cases.

[Unreleased]: https://github.com/snegi26/AgentGovernance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/snegi26/AgentGovernance/releases/tag/v0.1.0
