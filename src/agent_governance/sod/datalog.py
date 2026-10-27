# SPDX-License-Identifier: Apache-2.0
"""A small embedded Datalog evaluator that keeps a derivation for every derived fact.

Supported language: function-free Horn clauses with stratified negation, evaluated bottom-up
with the semi-naive algorithm. It exists so that every SoD verdict comes with a *proof path* —
the chain of rules and base facts that produced it — rather than an opaque yes/no.

Example::

    X, Y, Z = Var("X"), Var("Y"), Var("Z")
    program = Program([
        Rule(atom("path", X, Y), [atom("edge", X, Y)], name="base"),
        Rule(atom("path", X, Z), [atom("edge", X, Y), atom("path", Y, Z)], name="step"),
    ])
    model = program.evaluate([atom("edge", "a", "b"), atom("edge", "b", "c")])
    model.explain(atom("path", "a", "c"))
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

Constant = str | int | bool


@dataclass(frozen=True, slots=True)
class Var:
    name: str

    def __repr__(self) -> str:
        return f"?{self.name}"


Term = Var | Constant


@dataclass(frozen=True, slots=True)
class Atom:
    predicate: str
    args: tuple[Term, ...]

    def is_ground(self) -> bool:
        return not any(isinstance(arg, Var) for arg in self.args)

    def __repr__(self) -> str:
        return f"{self.predicate}({', '.join(map(repr, self.args))})"


def atom(predicate: str, *args: Term) -> Atom:
    return Atom(predicate, tuple(args))


@dataclass(frozen=True, slots=True)
class Literal:
    atom: Atom
    negated: bool = False


def neg(a: Atom) -> Literal:
    return Literal(a, negated=True)


@dataclass(frozen=True, slots=True)
class Rule:
    head: Atom
    body: tuple[Literal, ...]
    name: str

    def __init__(self, head: Atom, body: Sequence[Atom | Literal], name: str) -> None:
        if any(isinstance(arg, Var) and arg.name == "_" for arg in head.args):
            raise ValueError(f"rule {name!r} uses the wildcard in its head")
        counter = iter(range(1_000_000))
        literals = tuple(
            _rename_wildcards(b if isinstance(b, Literal) else Literal(b), counter) for b in body
        )
        object.__setattr__(self, "head", head)
        object.__setattr__(self, "body", literals)
        object.__setattr__(self, "name", name)
        self._check_safety()

    def _check_safety(self) -> None:
        positive_vars = {
            arg
            for lit in self.body
            if not lit.negated
            for arg in lit.atom.args
            if isinstance(arg, Var)
        }
        unsafe = [
            arg
            for a in (self.head, *(lit.atom for lit in self.body if lit.negated))
            for arg in a.args
            if isinstance(arg, Var) and not arg.name.startswith("_") and arg not in positive_vars
        ]
        if unsafe:
            raise ValueError(
                f"rule {self.name!r} is unsafe: {unsafe} not bound by a positive literal"
            )


def _rename_wildcards(lit: Literal, counter: Iterator[int]) -> Literal:
    """Give every ``_`` its own anonymous variable so wildcards never join with each other."""
    args = tuple(
        Var(f"_{next(counter)}") if isinstance(arg, Var) and arg.name == "_" else arg
        for arg in lit.atom.args
    )
    return Literal(Atom(lit.atom.predicate, args), lit.negated)


class StratificationError(ValueError):
    """The program has negation inside a recursive cycle and has no stratified meaning."""


@dataclass(frozen=True, slots=True)
class Derivation:
    rule: str
    premises: tuple[Atom, ...]


@dataclass(frozen=True, slots=True)
class Proof:
    """A derivation tree; ``rule`` is ``None`` for base facts."""

    fact: Atom
    rule: str | None
    children: tuple[Proof, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"fact": self.fact.predicate, "args": list(self.fact.args)}
        if self.rule is not None:
            out["rule"] = self.rule
            out["from"] = [child.to_dict() for child in self.children]
        return out

    def leaves(self) -> Iterator[Atom]:
        if not self.children:
            yield self.fact
        for child in self.children:
            yield from child.leaves()

    def walk(self) -> Iterator[Proof]:
        yield self
        for child in self.children:
            yield from child.walk()


class _Relation:
    """A set of ground tuples with lazily built per-position hash indexes."""

    __slots__ = ("_indexes", "rows")

    def __init__(self) -> None:
        self.rows: set[tuple[Constant, ...]] = set()
        self._indexes: dict[int, dict[Constant, list[tuple[Constant, ...]]]] = {}

    def add(self, row: tuple[Constant, ...]) -> bool:
        if row in self.rows:
            return False
        self.rows.add(row)
        for pos, index in self._indexes.items():
            index.setdefault(row[pos], []).append(row)
        return True

    def lookup(self, pos: int, value: Constant) -> Sequence[tuple[Constant, ...]]:
        index = self._indexes.get(pos)
        if index is None:
            index = defaultdict(list)
            for row in self.rows:
                index[row[pos]].append(row)
            self._indexes[pos] = index
        return index.get(value, ())


class Model:
    """The least model of a program over a set of base facts."""

    def __init__(self) -> None:
        self._relations: dict[str, _Relation] = defaultdict(_Relation)
        self._derivations: dict[Atom, Derivation] = {}

    def _relation(self, predicate: str) -> _Relation:
        return self._relations[predicate]

    def _add_base(self, fact: Atom) -> None:
        if not fact.is_ground():
            raise ValueError(f"base fact {fact!r} is not ground")
        self._relation(fact.predicate).add(fact.args)  # type: ignore[arg-type]

    def _add_derived(self, fact: Atom, derivation: Derivation) -> bool:
        added = self._relation(fact.predicate).add(fact.args)  # type: ignore[arg-type]
        if added:
            self._derivations[fact] = derivation
        return added

    def facts(self, predicate: str) -> list[Atom]:
        return [Atom(predicate, row) for row in self._relation(predicate).rows]

    def contains(self, fact: Atom) -> bool:
        return fact.args in self._relation(fact.predicate).rows

    def query(self, pattern: Atom) -> list[Atom]:
        """Ground facts matching ``pattern`` (variables match anything, repeats must agree)."""
        return [
            _substitute(pattern, binding)
            for binding in _match(self._relation(pattern.predicate), pattern, {})
        ]

    def explain(self, fact: Atom) -> Proof:
        """The derivation tree for ``fact``. Raises ``KeyError`` if the fact does not hold."""
        if not self.contains(fact):
            raise KeyError(fact)
        derivation = self._derivations.get(fact)
        if derivation is None:
            return Proof(fact, None)
        return Proof(fact, derivation.rule, tuple(self.explain(p) for p in derivation.premises))


class Program:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = tuple(rules)
        self._strata = _stratify(self.rules)

    def evaluate(self, facts: Iterable[Atom]) -> Model:
        model = Model()
        for fact in facts:
            model._add_base(fact)
        for stratum in self._strata:
            _evaluate_stratum(model, stratum)
        return model


def _stratify(rules: Sequence[Rule]) -> list[list[Rule]]:
    idb = {rule.head.predicate for rule in rules}
    # stratum[p] = smallest stratum consistent with: positive deps <=, negative deps <.
    stratum: dict[str, int] = dict.fromkeys(idb, 0)
    limit = len(idb) + 1
    changed = True
    while changed:
        changed = False
        for rule in rules:
            head = rule.head.predicate
            for lit in rule.body:
                dep = lit.atom.predicate
                if dep not in idb:
                    continue
                required = stratum[dep] + (1 if lit.negated else 0)
                if stratum[head] < required:
                    stratum[head] = required
                    changed = True
                    if required > limit:
                        raise StratificationError(
                            f"negation through recursion involving {head!r} and {dep!r}"
                        )
    layers: dict[int, list[Rule]] = defaultdict(list)
    for rule in rules:
        layers[stratum[rule.head.predicate]].append(rule)
    return [layers[i] for i in sorted(layers)]


def _evaluate_stratum(model: Model, rules: list[Rule]) -> None:
    heads = {rule.head.predicate for rule in rules}
    # First round: every rule against the full model.
    delta: dict[str, set[tuple[Constant, ...]]] = defaultdict(set)
    for rule in rules:
        for fact, premises in _fire(model, rule, delta_pos=None, delta=None):
            if model._add_derived(fact, Derivation(rule.name, premises)):
                delta[fact.predicate].add(fact.args)  # type: ignore[arg-type]
    # Semi-naive rounds: each recursive rule is re-fired with one body literal bound to delta.
    recursive = [
        (rule, i)
        for rule in rules
        for i, lit in enumerate(rule.body)
        if not lit.negated and lit.atom.predicate in heads
    ]
    while any(delta.values()):
        new_delta: dict[str, set[tuple[Constant, ...]]] = defaultdict(set)
        for rule, pos in recursive:
            for fact, premises in _fire(model, rule, delta_pos=pos, delta=delta):
                if model._add_derived(fact, Derivation(rule.name, premises)):
                    new_delta[fact.predicate].add(fact.args)  # type: ignore[arg-type]
        delta = new_delta


Binding = dict[Var, Constant]


def _fire(
    model: Model,
    rule: Rule,
    delta_pos: int | None,
    delta: Mapping[str, set[tuple[Constant, ...]]] | None,
) -> Iterator[tuple[Atom, tuple[Atom, ...]]]:
    positives = [(i, lit.atom) for i, lit in enumerate(rule.body) if not lit.negated]
    negatives = [lit.atom for lit in rule.body if lit.negated]
    if delta_pos is not None:
        # Evaluate the delta literal first: it is the smallest relation by construction.
        positives.sort(key=lambda item: item[0] != delta_pos)

    def join(index: int, binding: Binding) -> Iterator[Binding]:
        if index == len(positives):
            yield binding
            return
        pos, pattern = positives[index]
        candidates: Iterable[Binding]
        if pos == delta_pos and delta is not None:
            rows: Iterable[tuple[Constant, ...]] = delta.get(pattern.predicate, ())
            candidates = (
                b for b in (_unify(pattern, row, binding) for row in rows) if b is not None
            )
        else:
            candidates = _match(model._relation(pattern.predicate), pattern, binding)
        for extended in candidates:
            yield from join(index + 1, extended)

    for binding in join(0, {}):
        if any(_negation_holds(model, pattern, binding) for pattern in negatives):
            continue
        premises = tuple(_substitute(pattern, binding) for _, pattern in sorted(positives))
        yield _substitute(rule.head, binding), premises


def _negation_holds(model: Model, pattern: Atom, binding: Binding) -> bool:
    """True when some fact matches ``pattern`` under ``binding`` (so ``not pattern`` fails)."""
    return (
        next(iter(_match(model._relation(pattern.predicate), pattern, binding)), None) is not None
    )


def _match(relation: _Relation, pattern: Atom, binding: Binding) -> Iterator[Binding]:
    bound = [
        (i, binding[arg] if isinstance(arg, Var) else arg)
        for i, arg in enumerate(pattern.args)
        if not isinstance(arg, Var) or arg in binding
    ]
    rows: Iterable[tuple[Constant, ...]]
    if bound:
        pos, value = bound[0]
        rows = relation.lookup(pos, value)
    else:
        rows = list(relation.rows)
    for row in rows:
        extended = _unify(pattern, row, binding)
        if extended is not None:
            yield extended


def _unify(pattern: Atom, row: tuple[Constant, ...], binding: Binding) -> Binding | None:
    if len(row) != len(pattern.args):
        return None
    extended: Binding | None = None
    for arg, value in zip(pattern.args, row, strict=True):
        if isinstance(arg, Var):
            current = (extended or binding).get(arg)
            if current is None:
                if extended is None:
                    extended = dict(binding)
                extended[arg] = value
            elif current != value:
                return None
        elif arg != value:
            return None
    return extended if extended is not None else binding


def _substitute(pattern: Atom, binding: Binding) -> Atom:
    return Atom(
        pattern.predicate,
        tuple(binding.get(arg, arg) if isinstance(arg, Var) else arg for arg in pattern.args),
    )
