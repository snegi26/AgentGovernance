# SPDX-License-Identifier: Apache-2.0
"""Agentic access governance: deterministic verdicts, per-hop enforcement, evidence by default.

The package is layered so that nothing model-generated can produce a compliance verdict:

* :mod:`agent_governance.sod` — Datalog SoD engine (static, simulation, session checks).
* :mod:`agent_governance.identity` — principals, agent registry, RFC 8693 token exchange, DPoP.
* :mod:`agent_governance.policy` — Cedar policies and the tool catalogue.
* :mod:`agent_governance.approval` — signed, payload-bound human approvals.
* :mod:`agent_governance.gateway` — the per-call enforcement pipeline and its HTTP surface.
* :mod:`agent_governance.evidence` — hash-chained, append-only evidence and auditor packets.
"""

__version__ = "0.1.0"
