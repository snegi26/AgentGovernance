# SPDX-License-Identifier: Apache-2.0
"""Session-level SoD: deny a chain of individually permitted steps that forms a toxic pair.

A session accumulates executed ``(system, action, object_keys)`` steps. A proposed step
violates a risk when, within scope, another executed step performs the risk's other function
on a *related* object. Scope is the union of

* every step in the same ``plan_id`` (no time limit), and
* every step by the same delegating principal in the trailing 24 hours,

so splitting work across sessions or plans does not evade the check.

Relatedness is per risk, through its ``join_keys``: two steps are related unless both carry a
join key with *different* values. A step that lacks a join key is treated as related — when
relatedness is unknown the engine assumes the worst.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from agent_governance.core import Clock, SystemClock, canonical_json, isoformat, new_id
from agent_governance.model import Inventory
from agent_governance.sod.datalog import Atom, Program, Proof, Rule, Var, atom
from agent_governance.sod.ruleset import RiskLevel, RiskSpec, Ruleset

SESSION_WINDOW = timedelta(hours=24)


class SessionDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"

    @property
    def rank(self) -> int:
        return ("allow", "require_approval", "deny").index(self.value)


@dataclass(frozen=True, slots=True)
class SessionStep:
    """An executed (or proposed) step on a target system."""

    system: str
    action: str
    session_id: str
    plan_id: str
    delegator: str
    agent: str
    object_keys: Mapping[str, str] = field(default_factory=dict)
    ts: datetime | None = None
    step_id: str = field(default_factory=lambda: new_id("step"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "system": self.system,
            "action": self.action,
            "session_id": self.session_id,
            "plan_id": self.plan_id,
            "delegator": self.delegator,
            "agent": self.agent,
            "object_keys": dict(self.object_keys),
            "ts": isoformat(self.ts) if self.ts else None,
        }


class SessionStore(Protocol):
    def append(self, step: SessionStep) -> None: ...

    def in_scope(
        self,
        *,
        plan_id: str,
        delegator: str,
        since: datetime,
        actions: Iterable[tuple[str, str]],
    ) -> list[SessionStep]:
        """Executed steps matching ``actions`` that share the plan or the delegator's window."""
        ...


class SqliteSessionStore:
    """Reference session store. Use ``":memory:"`` for tests or a file path to persist."""

    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._db.executescript(
            """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS session_step (
                step_id TEXT PRIMARY KEY,
                system TEXT NOT NULL,
                action TEXT NOT NULL,
                session_id TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                delegator TEXT NOT NULL,
                agent TEXT NOT NULL,
                object_keys TEXT NOT NULL,
                ts TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_step_plan ON session_step(plan_id, system, action);
            CREATE INDEX IF NOT EXISTS ix_step_delegator
                ON session_step(delegator, system, action, ts);
            """
        )

    def append(self, step: SessionStep) -> None:
        if step.ts is None:
            raise ValueError("executed steps must carry a timestamp")
        with self._lock:
            self._db.execute(
                "INSERT INTO session_step VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    step.step_id,
                    step.system,
                    step.action,
                    step.session_id,
                    step.plan_id,
                    step.delegator,
                    step.agent,
                    canonical_json(dict(step.object_keys)).decode(),
                    isoformat(step.ts),
                ),
            )

    def in_scope(
        self,
        *,
        plan_id: str,
        delegator: str,
        since: datetime,
        actions: Iterable[tuple[str, str]],
    ) -> list[SessionStep]:
        pairs = sorted(set(actions))
        if not pairs:
            return []
        placeholders = ",".join("(?,?)" for _ in pairs)
        flat = [v for pair in pairs for v in pair]
        sql = f"""
            SELECT * FROM session_step
            WHERE (system, action) IN (VALUES {placeholders})
              AND (plan_id = ? OR (delegator = ? AND ts >= ?))
            ORDER BY ts
        """  # noqa: S608 - placeholders only, values are bound
        with self._lock:
            rows = self._db.execute(sql, [*flat, plan_id, delegator, isoformat(since)]).fetchall()
        return [
            SessionStep(
                step_id=row[0],
                system=row[1],
                action=row[2],
                session_id=row[3],
                plan_id=row[4],
                delegator=row[5],
                agent=row[6],
                object_keys=json.loads(row[7]),
                ts=datetime.fromisoformat(row[8].replace("Z", "+00:00")),
            )
            for row in rows
        ]


E1, E2, K, L, F, FA, FB, S, A = (Var(n) for n in ("E1", "E2", "K", "L", "F", "Fa", "Fb", "S", "A"))

SESSION_RULES = Program(
    [
        Rule(
            atom("step_performs", E1, F),
            [atom("step", E1, S, A), atom("function_action", F, S, A)],
            "step_performs_function",
        ),
        Rule(
            atom("session_violation", K, E1, E2),
            [
                atom("risk", K, L, FA, FB),
                atom("proposed", E1),
                atom("step_performs", E1, FA),
                atom("step_performs", E2, FB),
                atom("related", E1, E2, K),
            ],
            "proposed_completes_pair_a",
        ),
        Rule(
            atom("session_violation", K, E1, E2),
            [
                atom("risk", K, L, FA, FB),
                atom("proposed", E1),
                atom("step_performs", E1, FB),
                atom("step_performs", E2, FA),
                atom("related", E1, E2, K),
            ],
            "proposed_completes_pair_b",
        ),
        Rule(
            atom("session_critical", K, E1),
            [atom("critical_risk", K, L, F), atom("proposed", E1), atom("step_performs", E1, F)],
            "proposed_is_critical",
        ),
    ]
)


@dataclass(frozen=True, slots=True)
class SessionViolation:
    risk_id: str
    level: RiskLevel
    critical: bool
    conflicting_step: SessionStep | None
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
            "conflicting_step": self.conflicting_step.to_dict() if self.conflicting_step else None,
            "mitigated_by": list(self.mitigated_by),
            "proof": self.proof.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SessionResult:
    decision: SessionDecision
    proposed: SessionStep
    ruleset_version: str
    ruleset_digest: str
    violations: tuple[SessionViolation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": "session",
            "decision": self.decision.value,
            "proposed": self.proposed.to_dict(),
            "ruleset_version": self.ruleset_version,
            "ruleset_digest": self.ruleset_digest,
            "violations": [v.to_dict() for v in self.violations],
        }


def _related(a: Mapping[str, str], b: Mapping[str, str], join_keys: Sequence[str]) -> bool:
    return all(not (key in a and key in b and a[key] != b[key]) for key in join_keys)


class SessionChecker:
    """The spec's ``session_check(session_id, proposed_action)`` plus ``record`` after execution."""

    def __init__(
        self,
        ruleset: Ruleset,
        store: SessionStore,
        inventory: Inventory | None = None,
        clock: Clock | None = None,
        window: timedelta = SESSION_WINDOW,
    ) -> None:
        self.ruleset = ruleset
        self.store = store
        self.inventory = inventory
        self.clock = clock or SystemClock()
        self.window = window

    def check(self, proposed: SessionStep) -> SessionResult:
        now = self.clock.now()
        functions = self.ruleset.functions_by_action.get(
            (proposed.system, proposed.action), frozenset()
        )
        risks = {r.id: r for fn in functions for r in self.ruleset.risks_by_function.get(fn, ())}
        other_actions = {
            pair
            for risk in risks.values()
            if risk.function_b is not None
            for fn in (risk.function_a, risk.function_b)
            for pair in self.ruleset.function_actions(fn)
        }
        in_scope = self.store.in_scope(
            plan_id=proposed.plan_id,
            delegator=proposed.delegator,
            since=now - self.window,
            actions=other_actions,
        )
        # Only steps related to the proposal under at least one risk can complete a pair;
        # pruning them here keeps the Datalog fact base small on busy delegators.
        candidates = [
            c
            for c in in_scope
            if any(
                _related(proposed.object_keys, c.object_keys, r.join_keys)
                for r in risks.values()
                if r.function_b is not None
            )
        ]
        model = SESSION_RULES.evaluate(self._facts(proposed, candidates, risks.values()))
        by_id = {c.step_id: c for c in candidates}
        mitigations = self._mitigations(proposed.delegator, now)

        violations: dict[str, SessionViolation] = {}
        for fact in sorted(model.facts("session_violation"), key=lambda f: str(f.args)):
            risk_id = str(fact.args[0])
            if risk_id in violations:
                continue
            risk = risks[risk_id]
            violations[risk_id] = SessionViolation(
                risk_id=risk_id,
                level=risk.level,
                critical=False,
                conflicting_step=by_id[str(fact.args[2])],
                proof=model.explain(fact),
                mitigated_by=mitigations.get(risk_id, ()),
            )
        for fact in model.facts("session_critical"):
            risk = risks[str(fact.args[0])]
            violations[risk.id] = SessionViolation(
                risk_id=risk.id,
                level=risk.level,
                critical=True,
                conflicting_step=None,
                proof=model.explain(fact),
                mitigated_by=mitigations.get(risk.id, ()),
            )
        ordered = tuple(sorted(violations.values(), key=lambda v: (-v.level.rank, v.risk_id)))
        decision = max(
            (self._decide(v) for v in ordered), key=lambda d: d.rank, default=SessionDecision.ALLOW
        )
        return SessionResult(
            decision=decision,
            proposed=proposed,
            ruleset_version=self.ruleset.version,
            ruleset_digest=self.ruleset.digest,
            violations=ordered,
        )

    def record(self, step: SessionStep) -> SessionStep:
        """Persist an executed step; call only after the target system confirmed execution."""
        executed = step if step.ts is not None else replace(step, ts=self.clock.now())
        self.store.append(executed)
        return executed

    @staticmethod
    def _decide(violation: SessionViolation) -> SessionDecision:
        if violation.critical or violation.mitigated:
            # Critical access and mitigated pairs are high-risk writes: humans decide.
            return SessionDecision.REQUIRE_APPROVAL
        if violation.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return SessionDecision.DENY
        return SessionDecision.REQUIRE_APPROVAL

    def _facts(
        self, proposed: SessionStep, candidates: Sequence[SessionStep], risks: Iterable[RiskSpec]
    ) -> list[Atom]:
        risks = list(risks)
        functions = {fn for r in risks for fn in (r.function_a, r.function_b) if fn is not None}
        facts: list[Atom] = [atom("proposed", proposed.step_id)]
        for fn in functions:
            facts += [
                atom("function_action", fn, s, a) for s, a in self.ruleset.function_actions(fn)
            ]
        for risk in risks:
            if risk.function_b is None:
                facts.append(atom("critical_risk", risk.id, risk.level.value, risk.function_a))
                continue
            facts.append(atom("risk", risk.id, risk.level.value, risk.function_a, risk.function_b))
            facts += [
                atom("related", proposed.step_id, c.step_id, risk.id)
                for c in candidates
                if _related(proposed.object_keys, c.object_keys, risk.join_keys)
            ]
        for step in (proposed, *candidates):
            facts.append(atom("step", step.step_id, step.system, step.action))
        return facts

    def _mitigations(self, delegator: str, now: datetime) -> dict[str, tuple[str, ...]]:
        found: dict[str, list[str]] = {}
        sources = [*self.ruleset.mitigations()]
        if self.inventory is not None:
            sources += self.inventory.mitigations_for(delegator, now.date())
        for m in sources:
            if m.principal_id == delegator and m.active_on(now.date()):
                found.setdefault(m.risk_id, []).append(m.control_id)
        return {k: tuple(sorted(v)) for k, v in found.items()}
