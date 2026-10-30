# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest

from agent_governance.cli import main
from agent_governance.crypto import ed25519_public_b64
from agent_governance.demo.scenario import run_demo

FIXTURES = resources.files("agent_governance.fixtures")


def test_demo_all_guarantees_hold(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo", "--packet-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "FAIL" not in out
    assert (tmp_path / "AC-SOD-01.json").exists()
    assert (tmp_path / "AC-SOD-01.md").read_text().startswith("# Evidence packet")


def test_demo_steps_cover_all_spec_abuse_cases() -> None:
    titles = " ".join(step.title for step in run_demo())
    for phrase in (
        "Injected justification",
        "posts an invoice",
        "different payload",
        "expired",
        "another host",
    ):
        assert phrase in titles


def test_rules_validate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    starter = resources.files("agent_governance.rules.starter").joinpath("sap_s4.yaml")
    assert main(["rules", "validate", str(starter)]) == 0
    assert "starter-sap-2026.10" in capsys.readouterr().out
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "ruleset_version: x\nactions: []\nfunctions: []\n"
        "risks: [{id: r, level: high, function_a: nope}]\n"
    )
    assert main(["rules", "validate", str(bad)]) == 1


def test_sod_static_from_exports(capsys: pytest.CaptureFixture[str]) -> None:
    args = [
        "--sap",
        str(FIXTURES.joinpath("sap_s4.json")),
        "--entra",
        str(FIXTURES.joinpath("entra.json")),
    ]
    assert main(["sod", "static", "--principal", "user:sam@acme", *args]) == 0
    out = capsys.readouterr()
    assert [v["risk_id"] for v in json.loads(out.out)["violations"]] == ["P2P-01"]
    assert "RFC_ORPHAN has no human owner" in out.err
    assert "legacy-sync has no human owner" in out.err


def test_sod_simulate_and_unknown_principal(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(["sod", "simulate", "--principal", "user:priya@acme", "--add", "Z_VENDOR_MAINT"]) == 0
    )
    assert [v["risk_id"] for v in json.loads(capsys.readouterr().out)["added"]] == ["P2P-01"]
    assert main(["sod", "static", "--principal", "user:ghost@acme"]) == 2


def test_verify_packet_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from agent_governance.demo.estate import build_demo

    estate = build_demo()
    runtime = estate.runtime
    agent = estate.agent("access-request")
    token = agent.exchange(estate.user_token("user:priya@acme"), "iag", plan_id="p")
    agent.call(token, "iag.submit_request", {"roles": ["Z_VENDOR_MAINT"], "end_date": "2026-11-15"})
    runtime.anchor("2026-10-27")
    day = estate.clock.now().date()
    path = tmp_path / "packet.json"
    path.write_text(json.dumps(runtime.packet("AC-SOD-01", day, day)))
    signer = ed25519_public_b64(runtime.keys.packet_signing)
    tsa = ed25519_public_b64(runtime.keys.tsa)
    assert (
        main(["evidence", "verify-packet", str(path), f"--signer-key={signer}", f"--tsa-key={tsa}"])
        == 0
    )
    assert "packet OK" in capsys.readouterr().out
    other = ed25519_public_b64(runtime.keys.approval_signing)
    assert main(["evidence", "verify-packet", str(path), f"--signer-key={other}"]) == 1
    runtime.close()
