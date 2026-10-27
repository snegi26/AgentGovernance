# SPDX-License-Identifier: Apache-2.0
"""``agent-governance`` command line.

Commands:

* ``demo`` — run the end-to-end walkthrough; exits non-zero if any guarantee fails.
* ``rules validate PATH`` — validate a rule-set file and print its version and digest.
* ``sod static|simulate`` — run SoD checks against SAP/Entra exports (or the demo estate).
* ``evidence verify-packet PACKET`` — verify an auditor packet offline.
* ``serve`` — run the HTTP gateway over the demo estate (development only).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from agent_governance import __version__
from agent_governance.connectors.base import Connector, load_into
from agent_governance.connectors.entra import EntraConnector
from agent_governance.connectors.sap import SapS4Connector
from agent_governance.core import SystemClock
from agent_governance.crypto import ed25519_public_from_b64
from agent_governance.demo.estate import build_demo
from agent_governance.demo.scenario import run_demo
from agent_governance.evidence.packet import verify_packet
from agent_governance.gateway.http import create_app
from agent_governance.model import Inventory, UnknownEntityError
from agent_governance.runtime import Settings
from agent_governance.sod.engine import SodEngine
from agent_governance.sod.ruleset import Ruleset


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-governance", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the end-to-end walkthrough")
    demo.add_argument(
        "--packet-dir", type=Path, help="write the auditor packet (JSON + Markdown) here"
    )

    rules = sub.add_parser("rules", help="rule-set tools").add_subparsers(
        dest="rules_command", required=True
    )
    validate = rules.add_parser("validate", help="validate a rule-set YAML file")
    validate.add_argument("path", type=Path)

    sod = sub.add_parser("sod", help="SoD checks").add_subparsers(dest="sod_command", required=True)
    for name in ("static", "simulate"):
        cmd = sod.add_parser(name)
        cmd.add_argument("--principal", required=True)
        cmd.add_argument("--ruleset", type=Path, help="rule-set YAML (default: bundled starter)")
        cmd.add_argument("--sap", type=Path, help="SAP S/4HANA table export (JSON)")
        cmd.add_argument("--entra", type=Path, help="Microsoft Graph export (JSON)")
        if name == "simulate":
            cmd.add_argument("--add", nargs="*", default=[], metavar="ROLE")
            cmd.add_argument("--remove", nargs="*", default=[], metavar="ROLE")

    evidence = sub.add_parser("evidence", help="evidence tools").add_subparsers(
        dest="evidence_command", required=True
    )
    verify = evidence.add_parser("verify-packet", help="verify a packet offline")
    verify.add_argument("packet", type=Path)
    verify.add_argument(
        "--signer-key", required=True, help="trusted packet signer public key (base64url)"
    )
    verify.add_argument("--tsa-key", help="trusted TSA public key (base64url)")

    serve = sub.add_parser(
        "serve", help="run the HTTP gateway over the demo estate (development only)"
    )
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def _inventory(args: argparse.Namespace) -> Inventory:
    if args.sap is None and args.entra is None:
        return build_demo().runtime.inventory
    inventory = Inventory()
    connectors: list[Connector] = []
    if args.entra is not None:
        connectors.append(EntraConnector.from_file(args.entra))
    if args.sap is not None:
        connectors.append(SapS4Connector.from_file(args.sap))
    for warning in load_into(inventory, *connectors):
        print(f"warning: {warning}", file=sys.stderr)
    return inventory


def _sod(args: argparse.Namespace) -> int:
    ruleset = Ruleset.load(args.ruleset) if args.ruleset else Ruleset.starter()
    engine = SodEngine(ruleset, _inventory(args), SystemClock())
    try:
        if args.sod_command == "static":
            result = engine.static(args.principal).to_dict()
        else:
            result = engine.simulate(args.principal, args.add, args.remove).to_dict()
    except UnknownEntityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


def _verify_packet(args: argparse.Namespace) -> int:
    packet = json.loads(args.packet.read_text(encoding="utf-8"))
    result = verify_packet(
        packet,
        signer_key=ed25519_public_from_b64(args.signer_key),
        tsa_key=ed25519_public_from_b64(args.tsa_key) if args.tsa_key else None,
    )
    for warning in result.warnings:
        print(f"warning: {warning}")
    for error in result.errors:
        print(f"error: {error}")
    print("packet OK" if result.ok else "packet INVALID")
    return 0 if result.ok else 1


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn  # noqa: PLC0415 - optional [server] extra
    except ImportError:
        print(
            "serve needs the server extra: pip install 'agent-governance[server]'", file=sys.stderr
        )
        return 2
    estate = build_demo(
        clock=SystemClock(), settings=Settings(base_url=f"http://{args.host}:{args.port}")
    )
    print("Development server over the synthetic demo estate. Never expose it.", file=sys.stderr)
    for user in ("user:priya@acme", "user:mark@acme", "user:cora@acme"):
        token = estate.idp.issue_user_token(
            user, estate.runtime.settings.issuer, lifetime=timedelta(hours=1)
        )
        print(f"  {user} bearer token (1h): {token}", file=sys.stderr)
    uvicorn.run(create_app(estate.runtime), host=args.host, port=args.port)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "demo":
        print(f"agent-governance {__version__} demo (synthetic ACME estate)")
        steps = run_demo(sys.stdout, args.packet_dir)
        return 0 if all(step.passed for step in steps) else 1
    if args.command == "rules":
        try:
            ruleset = Ruleset.load(args.path)
        except (OSError, ValueError) as exc:
            print(f"invalid rule set: {exc}", file=sys.stderr)
            return 1
        counts = f"{len(ruleset.risks)} risks, {len(ruleset.functions)} functions"
        print(f"{ruleset.version} {ruleset.digest}: {counts}")
        return 0
    if args.command == "sod":
        return _sod(args)
    if args.command == "evidence":
        return _verify_packet(args)
    return _serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
