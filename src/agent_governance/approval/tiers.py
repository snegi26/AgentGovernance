# SPDX-License-Identifier: Apache-2.0
"""Approval tiers from the spec, and the approver roles each tier requires."""

from __future__ import annotations

from enum import StrEnum


class ApproverRole(StrEnum):
    LINE_MANAGER = "line_manager"
    ROLE_OWNER = "role_owner"
    CONTROL_OWNER = "control_owner"
    REVIEWER = "reviewer"
    SECURITY_ADMIN = "security_admin"
    AGENT_OWNER = "agent_owner"


class ApprovalTier(StrEnum):
    NONE = "none"
    LOW_RISK_WRITE = "low_risk_write"
    HIGH_RISK_WRITE = "high_risk_write"
    BULK_REVOKE = "bulk_revoke"
    AGENT_RESTORE = "agent_restore"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @property
    def required_roles(self) -> frozenset[ApproverRole]:
        return _REQUIRED[self]


_RANK = {
    ApprovalTier.NONE: 0,
    ApprovalTier.LOW_RISK_WRITE: 1,
    ApprovalTier.AGENT_RESTORE: 2,
    ApprovalTier.HIGH_RISK_WRITE: 3,
    ApprovalTier.BULK_REVOKE: 3,
}

_REQUIRED: dict[ApprovalTier, frozenset[ApproverRole]] = {
    ApprovalTier.NONE: frozenset(),
    ApprovalTier.LOW_RISK_WRITE: frozenset({ApproverRole.LINE_MANAGER}),
    ApprovalTier.HIGH_RISK_WRITE: frozenset({ApproverRole.ROLE_OWNER, ApproverRole.CONTROL_OWNER}),
    ApprovalTier.BULK_REVOKE: frozenset({ApproverRole.REVIEWER, ApproverRole.SECURITY_ADMIN}),
    ApprovalTier.AGENT_RESTORE: frozenset({ApproverRole.AGENT_OWNER}),
}

#: Bulk revoke threshold: more than this many lines in one certification action.
BULK_REVOKE_THRESHOLD = 25
#: Longest access request that still counts as low risk.
LOW_RISK_MAX_DAYS = 30


def strictest(*tiers: ApprovalTier) -> ApprovalTier:
    """The tier with the most approvers; ties keep the first (for example bulk over high)."""
    best = ApprovalTier.NONE
    for tier in tiers:
        if tier.rank > best.rank:
            best = tier
    return best
