# SPDX-License-Identifier: Apache-2.0
"""The evidence record: one per decision, immutable, linked into a per-tenant daily hash chain.

Chain construction::

    content_digest_i = sha256(canonical(record_i without prev_hash and hash))
    hash_i           = sha256(prev_hash_i + "\\n" + content_digest_i)
    prev_hash_0      = sha256("genesis\\n" + tenant + "\\n" + day)

Linking on the *content digest* rather than the full body lets an evidence packet prove that
a selected record sits in an anchored chain while disclosing only the digests of the records
it does not include.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from agent_governance.core import digest


class EvidenceKind(StrEnum):
    GATEWAY_DECISION = "gateway.decision"
    SOD_VERDICT = "sod.verdict"
    APPROVAL = "approval"
    AGENT_OUTPUT = "agent.output"
    TOKEN_EXCHANGE = "token.exchange"  # noqa: S105 - an event kind, not a secret
    REGISTRY_CHANGE = "registry.change"


def genesis_hash(tenant: str, day: str) -> str:
    return "sha256:" + hashlib.sha256(f"genesis\n{tenant}\n{day}".encode()).hexdigest()


def link_hash(prev_hash: str, content_digest: str) -> str:
    return "sha256:" + hashlib.sha256(f"{prev_hash}\n{content_digest}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    record_id: str
    ts: str
    tenant: str
    kind: str
    actor: Mapping[str, str | None]
    verdict: str
    session_id: str | None = None
    plan_id: str | None = None
    inputs_hash: str | None = None
    ruleset_version: str | None = None
    model_ref: str | None = None
    prompt_hash: str | None = None
    approver: str | None = None
    flags: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""

    @property
    def day(self) -> str:
        return self.ts[:10]

    def content(self) -> dict[str, Any]:
        body = asdict(self)
        body["actor"] = dict(self.actor)
        body.pop("prev_hash")
        body.pop("hash")
        body["flags"] = list(self.flags)
        return body

    def content_digest(self) -> str:
        return digest(self.content())

    def to_dict(self) -> dict[str, Any]:
        return {**self.content(), "prev_hash": self.prev_hash, "hash": self.hash}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        return cls(**{**data, "flags": tuple(data.get("flags", ()))})
