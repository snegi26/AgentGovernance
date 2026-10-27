# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agent_governance.sod.ruleset import Ruleset


def _minimal(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "ruleset_version": "test-1",
        "actions": [
            {
                "system": "S4",
                "action": "XK01",
                "permissions": [{"auth_object": "S_TCODE", "field": "TCD", "value": "XK01"}],
            },
            {
                "system": "S4",
                "action": "FB60",
                "permissions": [{"auth_object": "S_TCODE", "field": "TCD", "value": "FB60"}],
            },
        ],
        "functions": [
            {"id": "F_V", "actions": ["S4:XK01"]},
            {"id": "F_I", "actions": ["S4:FB60"]},
        ],
        "risks": [{"id": "R1", "level": "high", "function_a": "F_V", "function_b": "F_I"}],
    }
    data.update(overrides)
    return data


def test_starter_library_loads_and_compiles(ruleset: Ruleset) -> None:
    assert ruleset.version == "starter-sap-2026.10"
    assert ruleset.digest.startswith("sha256:")
    predicates = {fact.predicate for fact in ruleset.base_facts}
    assert predicates == {"action_permission", "function_action", "risk", "critical_risk"}
    assert ruleset.risks["P2P-01"].join_keys == ("vendor_id",)
    assert ruleset.risks["CRIT-01"].critical


def test_digest_changes_when_content_changes_even_if_version_does_not() -> None:
    a = Ruleset.from_dict(_minimal())
    b = Ruleset.from_dict(
        _minimal(risks=[{"id": "R1", "level": "medium", "function_a": "F_V", "function_b": "F_I"}])
    )
    assert a.version == b.version
    assert a.digest != b.digest


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {
                "functions": [
                    {"id": "F_V", "actions": ["S4:NOPE"]},
                    {"id": "F_I", "actions": ["S4:FB60"]},
                ]
            },
            "unknown action",
        ),
        (
            {"risks": [{"id": "R1", "level": "high", "function_a": "F_V", "function_b": "F_X"}]},
            "unknown function",
        ),
        (
            {"risks": [{"id": "R1", "level": "high", "function_a": "F_V", "function_b": "F_V"}]},
            "with itself",
        ),
        ({"risks": [{"id": "R1", "level": "severe", "function_a": "F_V"}]}, "level"),
        ({"ruleset_version": ""}, "ruleset_version"),
        (
            {
                "functions": [
                    {"id": "F_V", "actions": ["S4:XK01"]},
                    {"id": "F_V", "actions": ["S4:FB60"]},
                ]
            },
            "duplicate",
        ),
        (
            {
                "mitigations": [
                    {
                        "risk_id": "NOPE",
                        "principal_id": "u",
                        "control_id": "c",
                        "valid_to": "2027-01-01",
                    }
                ]
            },
            "unknown risk",
        ),
        ({"surprise": True}, "Extra inputs"),
    ],
)
def test_invalid_rulesets_are_rejected(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Ruleset.from_dict(_minimal(**overrides))


def test_actions_require_at_least_one_permission() -> None:
    data = _minimal()
    data["actions"][0]["permissions"] = []
    with pytest.raises(ValidationError):
        Ruleset.from_dict(data)


def test_load_from_file(tmp_path: Path) -> None:
    import yaml

    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(_minimal()))
    assert Ruleset.load(path).risks["R1"].function_b == "F_I"
