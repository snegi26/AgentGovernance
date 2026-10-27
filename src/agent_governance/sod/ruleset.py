# SPDX-License-Identifier: Apache-2.0
"""Versioned SoD rule sets: risks, business functions, actions and their technical permissions.

A rule set is authored as YAML (see ``rules/starter/sap_s4.yaml``) and compiled into the
Datalog base facts of the spec's rule model:

* ``risk(risk_id, level, function_a, function_b)`` — or ``critical_risk(risk_id, level, f)``
  when the risk is a single critical function;
* ``function_action(function_id, system, action)``;
* ``action_permission(system, action, auth_object, field, value)``.

Every verdict records ``ruleset_version`` and the content ``digest``, so a rule edit that
forgets to bump the version is still visible in the evidence.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from functools import cached_property
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agent_governance.core import digest
from agent_governance.model import Mitigation
from agent_governance.sod.datalog import Atom, atom


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ("low", "medium", "high", "critical").index(self.value)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PermissionSpec(_Strict):
    auth_object: str
    field: str
    value: str


class ActionSpec(_Strict):
    system: str
    action: str
    description: str = ""
    permissions: tuple[PermissionSpec, ...] = Field(min_length=1)

    @property
    def key(self) -> str:
        return f"{self.system}:{self.action}"


class FunctionSpec(_Strict):
    id: str
    description: str = ""
    actions: tuple[str, ...] = Field(min_length=1, description="action keys, SYSTEM:ACTION")


class RiskSpec(_Strict):
    id: str
    level: RiskLevel
    description: str = ""
    function_a: str
    function_b: str | None = None
    join_keys: tuple[str, ...] = Field(
        default=(),
        description="object keys that make two executed actions related for session SoD",
    )

    @property
    def critical(self) -> bool:
        return self.function_b is None


class MitigationSpec(_Strict):
    risk_id: str
    principal_id: str
    control_id: str
    valid_to: date


class RulesetSpec(_Strict):
    ruleset_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    description: str = ""
    actions: tuple[ActionSpec, ...]
    functions: tuple[FunctionSpec, ...]
    risks: tuple[RiskSpec, ...]
    mitigations: tuple[MitigationSpec, ...] = ()

    @field_validator("actions", "functions", "risks")
    @classmethod
    def _unique(cls, items: tuple[Any, ...]) -> tuple[Any, ...]:
        keys = [getattr(item, "key", None) or item.id for item in items]
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        if dupes:
            raise ValueError(f"duplicate ids: {dupes}")
        return items

    @model_validator(mode="after")
    def _references_resolve(self) -> RulesetSpec:
        action_keys = {a.key for a in self.actions}
        function_ids = {f.id for f in self.functions}
        errors = [
            f"function {f.id} references unknown action {key}"
            for f in self.functions
            for key in f.actions
            if key not in action_keys
        ]
        for risk in self.risks:
            for fn in (risk.function_a, risk.function_b):
                if fn is not None and fn not in function_ids:
                    errors.append(f"risk {risk.id} references unknown function {fn}")
            if risk.function_a == risk.function_b:
                errors.append(f"risk {risk.id} pairs function {risk.function_a} with itself")
        risk_ids = {r.id for r in self.risks}
        errors += [
            f"mitigation for unknown risk {m.risk_id}"
            for m in self.mitigations
            if m.risk_id not in risk_ids
        ]
        if errors:
            raise ValueError("; ".join(errors))
        return self


@dataclass(frozen=True)
class Ruleset:
    """A validated, immutable rule set with its compiled base facts and lookup indexes."""

    spec: RulesetSpec

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Ruleset:
        return cls(RulesetSpec.model_validate(data))

    @classmethod
    def load(cls, path: str | Path) -> Ruleset:
        with Path(path).open(encoding="utf-8") as handle:
            return cls.from_dict(yaml.safe_load(handle))

    @classmethod
    def starter(cls, name: str = "sap_s4") -> Ruleset:
        """One of the bundled starter libraries (``sap_s4``)."""
        source = resources.files("agent_governance.rules.starter").joinpath(f"{name}.yaml")
        return cls.from_dict(yaml.safe_load(source.read_text(encoding="utf-8")))

    @property
    def version(self) -> str:
        return self.spec.ruleset_version

    @cached_property
    def digest(self) -> str:
        return digest(self.spec.model_dump(mode="json"))

    @cached_property
    def risks(self) -> dict[str, RiskSpec]:
        return {risk.id: risk for risk in self.spec.risks}

    @cached_property
    def functions(self) -> dict[str, FunctionSpec]:
        return {fn.id: fn for fn in self.spec.functions}

    @cached_property
    def actions(self) -> dict[str, ActionSpec]:
        return {a.key: a for a in self.spec.actions}

    @cached_property
    def functions_by_action(self) -> dict[tuple[str, str], frozenset[str]]:
        index: dict[tuple[str, str], set[str]] = defaultdict(set)
        for fn in self.spec.functions:
            for key in fn.actions:
                action = self.actions[key]
                index[(action.system, action.action)].add(fn.id)
        return {k: frozenset(v) for k, v in index.items()}

    @cached_property
    def risks_by_function(self) -> dict[str, tuple[RiskSpec, ...]]:
        index: dict[str, list[RiskSpec]] = defaultdict(list)
        for risk in self.spec.risks:
            index[risk.function_a].append(risk)
            if risk.function_b is not None:
                index[risk.function_b].append(risk)
        return {k: tuple(v) for k, v in index.items()}

    def function_actions(self, function_id: str) -> list[tuple[str, str]]:
        return [
            (self.actions[k].system, self.actions[k].action)
            for k in self.functions[function_id].actions
        ]

    @cached_property
    def permissions_by_object(self) -> dict[tuple[str, str, str], tuple[tuple[str, str], ...]]:
        """(system, auth_object, field) -> ((action, required_value), ...)."""
        index: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
        for action in self.spec.actions:
            for perm in action.permissions:
                index[(action.system, perm.auth_object, perm.field)].append(
                    (action.action, perm.value)
                )
        return {k: tuple(v) for k, v in index.items()}

    def mitigations(self) -> list[Mitigation]:
        return [
            Mitigation(m.risk_id, m.principal_id, m.control_id, m.valid_to)
            for m in self.spec.mitigations
        ]

    @cached_property
    def base_facts(self) -> tuple[Atom, ...]:
        return tuple(self._base_facts())

    def _base_facts(self) -> Iterable[Atom]:
        for action in self.spec.actions:
            for perm in action.permissions:
                yield atom(
                    "action_permission",
                    action.system,
                    action.action,
                    perm.auth_object,
                    perm.field,
                    perm.value,
                )
        for fn in self.spec.functions:
            for key in fn.actions:
                yield atom(
                    "function_action", fn.id, self.actions[key].system, self.actions[key].action
                )
        for risk in self.spec.risks:
            if risk.function_b is None:
                yield atom("critical_risk", risk.id, risk.level.value, risk.function_a)
            else:
                yield atom("risk", risk.id, risk.level.value, risk.function_a, risk.function_b)
