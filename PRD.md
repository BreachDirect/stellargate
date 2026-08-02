# PRD — StellarGate

**Unified Stellar DevSecOps Gate**

## Problem

The Stellar Wave program (Drips) has produced four independent security/quality
tools, each built by different contributors in different waves, each solving
one slice of the same problem:

| Tool | Layer | Output |
|---|---|---|
| RytScan | Soroban contract static analysis | JSON, CLI, `--fail-on` |
| SchemaLock | API contract stability (error envelopes, auth boundaries) | JSON report, CLI, exit code |
| VaultSweep | Secrets/credential leakage in repo & CI | JSON, CLI, `--fail-on` |
| ShieldScan | Web app vulnerability scanning (OWASP) | HTML/MD report, web dashboard |

A Stellar backend team today has to run all four separately, in different
languages/runtimes, with no combined pass/fail signal and no single report to
attach to a PR. Nothing wires them together. That's the gap StellarGate fills.

## Goal

One command (`stellargate run`) and one GitHub Action that runs all
configured tools against a repo, normalizes every finding into one schema,
and produces a single compliance report + merge-blocking status check.

## Non-goals (explicitly out of scope for this project)

- Rewriting or replacing any of the four underlying tools
- Building new detection rules — StellarGate orchestrates, it doesn't detect
- A hosted SaaS dashboard (out of scope until traction justifies it)

## Users

Stellar Wave contributors and backend teams who want one CI gate instead of
four disconnected ones.

## Success metrics (Phase 1)

- `stellargate run` executes against a real target repo and produces a
  correct, readable compliance report combining output from at least
  RytScan, SchemaLock, and VaultSweep (ShieldScan deferred — see Phase 2).
- Exit code is non-zero when any finding meets the configured severity
  threshold, zero otherwise — verified against fixture repos with known
  planted issues.
- A team can adopt it by writing one `stellargate.yaml` file — no code
  changes to their own repo required.

## Phases

**Phase 1 (this build):** Core orchestrator, unified finding schema,
config format, adapters for RytScan / SchemaLock / VaultSweep, aggregation,
JSON + Markdown report generation, CLI entrypoint, test suite against
fixtures. Runnable locally.

**Phase 2 (issues only, not built yet):** ShieldScan adapter (needs a
CLI/JSON mode added upstream or driven headlessly), GitHub Action wrapper,
PR sticky-comment bot, commit status check.

**Phase 3 (issues only, not built yet):** Docs site, self-scanning
(dogfooding StellarGate on its own repo), severity-threshold presets
(`--strict` / `--standard`), toolchain auto-install/caching for CI.
