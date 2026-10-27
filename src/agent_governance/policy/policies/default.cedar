// SPDX-License-Identifier: Apache-2.0
//
// Default gateway policy set. Evaluated per tool call with
//   principal = Agent::"<agent principal id>"
//   action    = Action::"<tool id>"   (member of Action::"class:<action class>")
//   resource  = Resource::"<server>/<resource type>"
// and a context built by the gateway from the verified token, the SoD engine and the
// approval service. Every verdict input is deterministic; nothing here reads model output.

// --- Permits: the contract ∩ delegator intersection ----------------------------------------

@id("read-draft.within-contract")
permit (
  principal is Agent,
  action in [Action::"class:read", Action::"class:draft"],
  resource
)
when {
  principal.allowed_tools.contains(context.tool_id) &&
  context.token_scope.contains(context.tool_id) &&
  (context.delegator.kind == "human" || context.delegator.kind == "trigger") &&
  context.delegator.entitlements.contains(context.required_entitlement)
};

@id("write.within-contract")
permit (
  principal is Agent,
  action in [Action::"class:write", Action::"class:grant", Action::"class:revoke"],
  resource
)
when {
  principal.allowed_tools.contains(context.tool_id) &&
  context.token_scope.contains(context.tool_id) &&
  (context.delegator.kind == "human" || context.delegator.kind == "trigger") &&
  context.delegator.entitlements.contains(context.required_entitlement)
};

// --- Forbids: these override any permit -------------------------------------------------------

@id("autonomy.read-only-agents-cannot-draft")
forbid (principal is Agent, action in Action::"class:draft", resource)
when { principal.max_autonomy == "read" };

@id("autonomy.writes-need-write-autonomy")
forbid (
  principal is Agent,
  action in [Action::"class:write", Action::"class:grant", Action::"class:revoke"],
  resource
)
unless { principal.max_autonomy == "write_with_approval" || principal.max_autonomy == "write" };

@id("quarantine.no-writes")
forbid (
  principal is Agent,
  action in [Action::"class:write", Action::"class:grant", Action::"class:revoke"],
  resource
)
when { principal.quarantined };

@id("sod.deny-is-final")
forbid (principal, action, resource)
when { context.sod.verdict == "deny" };

@id("approval.required-and-bound-to-payload")
forbid (
  principal is Agent,
  action in [Action::"class:write", Action::"class:grant", Action::"class:revoke"],
  resource
)
when { context.approval_required }
unless { context.approval.valid && context.approval.payload_hash == context.call_hash };

// Grants, role changes and firefighter activation always need a named human approver.
@id("approval.grants-always")
forbid (principal is Agent, action in Action::"class:grant", resource)
unless { context.approval.valid && context.approval.payload_hash == context.call_hash };

// Untrusted text that looks like an instruction never rides an unapproved write.
@id("injection.flagged-writes-need-approval")
forbid (
  principal is Agent,
  action in [Action::"class:write", Action::"class:grant", Action::"class:revoke"],
  resource
)
when { context.flags.contains("possible_injection") }
unless { context.approval.valid && context.approval.payload_hash == context.call_hash };
