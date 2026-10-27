# SPDX-License-Identifier: Apache-2.0
"""Static and what-if SoD checks over one rule model, each violation carrying its proof path."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from agent_governance.core import Clock, SystemClock
from agent_governance.model import Assignment, Inventory, Role
from agent_governance.sod.datalog import Atom, Model, Program, Proof, Rule, Var, atom, neg
from agent_governance.sod.ruleset import RiskLevel, Ruleset

_ = Var("_")
P, R, S, A, F, K, L = (Var(n) for n in ("P", "R", "S", "A", "F", "K", "L"))
FA, FB, OBJ, FLD, V = Var("Fa"), Var("Fb"), Var("Obj"), Var("Fld"), Var("V")

#: The assignment-level rule program. ``has_perm`` is computed outside Datalog because it
#: needs wildcard matching of authorization values (``*`` and ``FB*``).
ASSIGNMENT_RULES = Program(
    [
        Rule(
            atom("action_exists", S, A), [atom("action_permission", S, A, _, _, _)], "action_exists"
        ),
        Rule(
            atom("role_missing", R, S, A),
            [
                atom("role_system", R, S),
                atom("action_permission", S, A, OBJ, FLD, V),
                neg(atom("has_perm", R, S, OBJ, FLD, V)),
            ],
            "role_missing_permission",
        ),
        Rule(
            atom("role_action", R, S, A),
            [
                atom("role_system", R, S),
                atom("action_exists", S, A),
                neg(atom("role_missing", R, S, A)),
            ],
            "role_grants_action",
        ),
        Rule(
            atom("principal_function", P, F, R, S, A),
            [
                atom("assigned", P, R),
                atom("role_action", R, S, A),
                atom("function_action", F, S, A),
            ],
            "principal_performs_function",
        ),
        Rule(
            atom("sod_violation", P, K),
            [
                atom("risk", K, L, FA, FB),
                atom("principal_function", P, FA, _, _, _),
                atom("principal_function", P, FB, _, _, _),
            ],
            "conflicting_functions",
        ),
        Rule(
            atom("sod_violation", P, K),
            [atom("critical_risk", K, L, F), atom("principal_function", P, F, _, _, _)],
            "critical_function",
        ),
    ]
)


@dataclass(frozen=True, slots=True)
class PathStep:
    """One hop of a proof path: ``function`` is reachable through ``role`` via ``system:action``.

    ``authorizations`` lists the ``(auth_object, field, value)`` rows the role satisfied. They
    are listed separately because the Datalog proof reaches ``role_action`` through negation
    (no required permission is missing), and negated premises do not appear in a proof tree.
    """

    function: str
    role: str
    system: str
    action: str
    authorizations: tuple[tuple[str, str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "role": self.role,
            "system": self.system,
            "action": self.action,
            "authorizations": [list(a) for a in self.authorizations],
        }


@dataclass(frozen=True, slots=True)
class Violation:
    risk_id: str
    level: RiskLevel
    critical: bool
    functions: tuple[str, ...]
    path: tuple[PathStep, ...]
    proof: Proof
    mitigated_by: tuple[str, ...] = ()

    @property
    def mitigated(self) -> bool:
        return bool(self.mitigated_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_id": self.risk_id,
            "level": self.level.value,
            "critical": self.critical,
            "functions": list(self.functions),
            "mitigated_by": list(self.mitigated_by),
            "path": [step.to_dict() for step in self.path],
            "proof": self.proof.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class StaticResult:
    principal_id: str
    as_of: date
    ruleset_version: str
    ruleset_digest: str
    violations: tuple[Violation, ...]

    @property
    def unmitigated(self) -> tuple[Violation, ...]:
        return tuple(v for v in self.violations if not v.mitigated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": "static",
            "principal_id": self.principal_id,
            "as_of": self.as_of.isoformat(),
            "ruleset_version": self.ruleset_version,
            "ruleset_digest": self.ruleset_digest,
            "violations": [v.to_dict() for v in self.violations],
        }


@dataclass(frozen=True, slots=True)
class SimulationResult:
    principal_id: str
    add_roles: tuple[str, ...]
    remove_roles: tuple[str, ...]
    before: StaticResult
    after: StaticResult
    added: tuple[Violation, ...] = field(default=())
    removed: tuple[Violation, ...] = field(default=())

    @property
    def ruleset_version(self) -> str:
        return self.after.ruleset_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": "simulation",
            "principal_id": self.principal_id,
            "add_roles": list(self.add_roles),
            "remove_roles": list(self.remove_roles),
            "ruleset_version": self.after.ruleset_version,
            "ruleset_digest": self.after.ruleset_digest,
            "added": [v.to_dict() for v in self.added],
            "removed": [v.to_dict() for v in self.removed],
            "unchanged": sorted(
                {v.risk_id for v in self.after.violations} - {v.risk_id for v in self.added}
            ),
        }


class SodEngine:
    """Evaluates the rule model against a principal's (current or hypothetical) assignments."""

    def __init__(self, ruleset: Ruleset, inventory: Inventory, clock: Clock | None = None) -> None:
        self.ruleset = ruleset
        self.inventory = inventory
        self.clock = clock or SystemClock()

    def static(self, principal_id: str, as_of: date | None = None) -> StaticResult:
        day = as_of or self.clock.now().date()
        self.inventory.principal(principal_id)  # unknown principals are an error, not "clean"
        roles = [
            self.inventory.role(a.role_id)
            for a in self.inventory.assignments_for(principal_id, day)
        ]
        return self._evaluate(principal_id, roles, day)

    def simulate(
        self,
        principal_id: str,
        add_roles: Sequence[str] = (),
        remove_roles: Sequence[str] = (),
        as_of: date | None = None,
    ) -> SimulationResult:
        day = as_of or self.clock.now().date()
        before = self.static(principal_id, day)
        current = {a.role_id for a in self.inventory.assignments_for(principal_id, day)}
        hypothetical = (current - set(remove_roles)) | set(add_roles)
        after = self._evaluate(
            principal_id, [self.inventory.role(r) for r in sorted(hypothetical)], day
        )
        before_ids = {v.risk_id for v in before.violations}
        after_ids = {v.risk_id for v in after.violations}
        return SimulationResult(
            principal_id=principal_id,
            add_roles=tuple(add_roles),
            remove_roles=tuple(remove_roles),
            before=before,
            after=after,
            added=tuple(v for v in after.violations if v.risk_id not in before_ids),
            removed=tuple(v for v in before.violations if v.risk_id not in after_ids),
        )

    def evaluate_assignments(
        self, principal_id: str, assignments: Iterable[Assignment], as_of: date
    ) -> StaticResult:
        """Check an explicit assignment set, e.g. one read straight from a connector."""
        roles = [self.inventory.role(a.role_id) for a in assignments if a.active_on(as_of)]
        return self._evaluate(principal_id, roles, as_of)

    def _evaluate(self, principal_id: str, roles: Sequence[Role], day: date) -> StaticResult:
        facts = [*self.ruleset.base_facts, *self._role_facts(principal_id, roles)]
        model = ASSIGNMENT_RULES.evaluate(facts)
        mitigations: dict[str, list[str]] = {}
        for m in [*self.inventory.mitigations_for(principal_id, day), *self.ruleset.mitigations()]:
            if m.principal_id == principal_id and m.active_on(day):
                mitigations.setdefault(m.risk_id, []).append(m.control_id)
        violations = sorted(
            (self._violation(model, fact, mitigations) for fact in model.facts("sod_violation")),
            key=lambda v: (-v.level.rank, v.risk_id),
        )
        return StaticResult(
            principal_id=principal_id,
            as_of=day,
            ruleset_version=self.ruleset.version,
            ruleset_digest=self.ruleset.digest,
            violations=tuple(violations),
        )

    def _role_facts(self, principal_id: str, roles: Sequence[Role]) -> list[Atom]:
        index = self.ruleset.permissions_by_object
        facts: list[Atom] = []
        for role in roles:
            facts.append(atom("assigned", principal_id, role.role_id))
            facts.append(atom("role_system", role.role_id, role.system))
            for ent in role.entitlements:
                if ent.system != role.system:
                    continue
                for _action, required in index.get((ent.system, ent.auth_object, ent.field), ()):
                    if ent.satisfies(required):
                        facts.append(
                            atom(
                                "has_perm",
                                role.role_id,
                                ent.system,
                                ent.auth_object,
                                ent.field,
                                required,
                            )
                        )
        return facts

    def _violation(self, model: Model, fact: Atom, mitigations: dict[str, list[str]]) -> Violation:
        risk_id = str(fact.args[1])
        risk = self.ruleset.risks[risk_id]
        proof = model.explain(fact)
        path = tuple(
            self._path_step(model, *(str(arg) for arg in n.fact.args[1:]))
            for n in proof.children
            if n.fact.predicate == "principal_function"
        )
        functions = (
            (risk.function_a,) if risk.function_b is None else (risk.function_a, risk.function_b)
        )
        return Violation(
            risk_id=risk_id,
            level=risk.level,
            critical=risk.critical,
            functions=functions,
            path=path,
            proof=proof,
            mitigated_by=tuple(sorted(mitigations.get(risk_id, ()))),
        )

    def _path_step(
        self, model: Model, function: str, role: str, system: str, action: str
    ) -> PathStep:
        spec = self.ruleset.actions[f"{system}:{action}"]
        held = tuple(
            (perm.auth_object, perm.field, perm.value)
            for perm in spec.permissions
            if model.contains(
                atom("has_perm", role, system, perm.auth_object, perm.field, perm.value)
            )
        )
        return PathStep(function, role, system, action, held)
