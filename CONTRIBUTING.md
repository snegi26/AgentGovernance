# Contributing

Thanks for helping. This project governs access decisions, so the bar for changes to verdict, enforcement and evidence code is high. Read [docs/architecture.md](docs/architecture.md) first.

## Development setup

```bash
uv sync                                   # Python 3.11+
uv run pytest                             # full suite; warnings are errors
uv run pytest -m "not perf"               # skip latency benchmarks
uv run ruff format && uv run ruff check   # formatting and lint
uv run mypy                               # strict type checking
uv run lint-imports                       # verdict code must not import agents or model SDKs
uv run agent-governance demo              # end-to-end smoke test
```

CI runs all of these on Python 3.11, 3.12 and 3.13 and requires 85% branch coverage.

## Ground rules

1. **Verdicts stay deterministic.** Nothing in `sod/`, `policy/`, `approval/`, `gateway/`, `evidence/` or `identity/` may call a model or depend on model output for a decision. `lint-imports` enforces that none of them imports `agent_governance.agents` or a model SDK, even indirectly.
2. **Fail closed.** A new dependency on the write path must deny when it is unavailable, and needs a test that shows it.
3. **Evidence before action.** Any new decision point writes an evidence record before the action proceeds.
4. **Tests at the highest seam.** Prefer tests through `Gateway.handle`, `TokenService.exchange` or `SodEngine` over private helpers. Expected values come from the spec or hand-worked examples, never from re-running the implementation. A new guard needs a test that fails when the guard is removed.
5. **Rule-set changes** bump `ruleset_version` and explain the source of each authorization value in the pull request.
6. Every source file starts with `# SPDX-License-Identifier: Apache-2.0`.

## Pull requests

Keep each pull request to one concern, describe the behaviour change and how it was verified, and add a line to `CHANGELOG.md` under *Unreleased*. By contributing you agree that your contribution is licensed under the Apache License 2.0.

## Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
