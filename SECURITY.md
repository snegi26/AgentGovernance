# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report them privately through GitHub's [private vulnerability reporting](https://github.com/snegi26/AgentGovernance/security/advisories/new) for this repository.

Include what you found, how to reproduce it, and the impact you expect. We aim to acknowledge reports within 3 working days and to agree on a disclosure timeline with you.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes (alpha: fixes land on `main`) |

## Scope

In scope: anything that lets an agent complete a write without the required engine verdict and human approval; bypasses of DPoP, token audience, scope or revocation; approval forgery or reuse; evidence tampering that verification does not detect; and fail-open behaviour when a dependency is unavailable.

The threat model and the assumptions deployments must meet are in [docs/security-model.md](docs/security-model.md). The demo estate, the `serve` command and the local IdP and TSA are development tools and are out of scope.
