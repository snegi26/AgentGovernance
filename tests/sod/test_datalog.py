# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import pytest

from agent_governance.sod.datalog import (
    Program,
    Rule,
    StratificationError,
    Var,
    atom,
    neg,
)

X, Y, Z = Var("X"), Var("Y"), Var("Z")

PATH = Program(
    [
        Rule(atom("path", X, Y), [atom("edge", X, Y)], name="base"),
        Rule(atom("path", X, Z), [atom("edge", X, Y), atom("path", Y, Z)], name="step"),
    ]
)


def test_recursive_closure_terminates_on_cycles() -> None:
    edges = [atom("edge", "a", "b"), atom("edge", "b", "c"), atom("edge", "c", "a")]
    model = PATH.evaluate(edges)
    pairs = {f.args for f in model.facts("path")}
    assert pairs == {(s, t) for s in "abc" for t in "abc"}


def test_explain_returns_derivation_down_to_base_facts() -> None:
    model = PATH.evaluate([atom("edge", "a", "b"), atom("edge", "b", "c")])
    proof = model.explain(atom("path", "a", "c"))
    assert proof.rule == "step"
    assert set(proof.leaves()) == {atom("edge", "a", "b"), atom("edge", "b", "c")}
    assert proof.to_dict()["from"][0] == {"fact": "edge", "args": ["a", "b"]}


def test_explain_unknown_fact_raises() -> None:
    model = PATH.evaluate([atom("edge", "a", "b")])
    with pytest.raises(KeyError):
        model.explain(atom("path", "b", "a"))


def test_stratified_negation_universal_quantification() -> None:
    # A role grants an action only if it holds *every* required permission.
    R, A, P = Var("R"), Var("A"), Var("P")
    program = Program(
        [
            Rule(
                atom("missing", R, A),
                [atom("role", R), atom("req", A, P), neg(atom("has", R, P))],
                "m",
            ),
            Rule(
                atom("grants", R, A),
                [atom("role", R), atom("req", A, Var("_")), neg(atom("missing", R, A))],
                "g",
            ),
        ]
    )
    facts = [
        atom("role", "full"),
        atom("role", "partial"),
        atom("req", "FB60", "tcode"),
        atom("req", "FB60", "bukrs"),
        atom("has", "full", "tcode"),
        atom("has", "full", "bukrs"),
        atom("has", "partial", "tcode"),
    ]
    model = program.evaluate(facts)
    assert {f.args for f in model.facts("grants")} == {("full", "FB60")}


def test_wildcards_do_not_join_with_each_other() -> None:
    program = Program([Rule(atom("q", X), [atom("p", X, Var("_"), Var("_"))], "w")])
    model = program.evaluate([atom("p", "a", 1, 2)])
    assert model.contains(atom("q", "a"))
    # premises are fully ground, so the proof is explainable
    assert model.explain(atom("q", "a")).children[0].fact == atom("p", "a", 1, 2)


def test_constants_and_repeated_variables_filter() -> None:
    program = Program([Rule(atom("self_loop", X), [atom("edge", X, X)], "s")])
    model = program.evaluate([atom("edge", "a", "a"), atom("edge", "a", "b")])
    assert {f.args for f in model.facts("self_loop")} == {("a",)}
    assert model.query(atom("edge", "a", Y)) == model.query(atom("edge", "a", Y))
    assert {f.args for f in model.query(atom("edge", X, "b"))} == {("a", "b")}


def test_falsy_constants_are_values_not_missing() -> None:
    program = Program([Rule(atom("q", X, Y), [atom("p", X, Y)], "c")])
    model = program.evaluate([atom("p", 0, ""), atom("p", False, 0)])
    assert {f.args for f in model.facts("q")} == {(0, ""), (False, 0)}


def test_negation_through_recursion_is_rejected() -> None:
    with pytest.raises(StratificationError):
        Program([Rule(atom("p", X), [atom("d", X), neg(atom("p", X))], "bad")])


def test_unsafe_rules_are_rejected() -> None:
    with pytest.raises(ValueError, match="unsafe"):
        Rule(atom("p", X, Y), [atom("q", X)], "unsafe")
    with pytest.raises(ValueError, match="unsafe"):
        Rule(atom("p", X), [atom("q", X), neg(atom("r", Y))], "unsafe-neg")
    with pytest.raises(ValueError, match="wildcard"):
        Rule(atom("p", Var("_")), [atom("q", X)], "wild-head")


def test_non_ground_base_fact_rejected() -> None:
    with pytest.raises(ValueError, match="not ground"):
        PATH.evaluate([atom("edge", X, "a")])
