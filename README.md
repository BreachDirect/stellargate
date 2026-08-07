# StellarGate

Unified Stellar DevSecOps Gate — one CLI, one report, four Stellar Wave
security tools.

StellarGate orchestrates [RytScan](https://github.com/BreachDirect/RytScan)
(Soroban contract security), [SchemaLock](https://github.com/BreachDirect/schemalock)
(API contract locking), and [VaultSweep](https://github.com/BreachDirect/vaultsweep)
(secrets scanning) into a single compliance report with one pass/fail exit
code. ShieldScan integration is planned for Phase 2 (see `architecture.md`).

See `PRD.md` for the product goal and `architecture.md` for how it's built.

## Status

**Phase 1 — complete.** Core orchestrator, config, three working adapters,
aggregation, JSON + Markdown reporting, CLI, full unit test coverage on
fixtures.

**Phase 2 / Phase 3 — not built yet.** Tracked as GitHub issues: ShieldScan
adapter, GitHub Action, PR comment bot, docs site, dogfooding.

## Install

Dependency versions are pinned for reproducible installs (see
`requirements.in` / `requirements-dev.in` for the source requirements and
`requirements.txt` / `requirements-dev.txt` for the compiled lockfiles):

```bash
pip install -r requirements-dev.txt
pip install -e .
```

Lockfiles are generated with `uv pip compile` (pip-tools style); to refresh
them after editing the `.in` files:

```bash
uv pip compile requirements.in -o requirements.txt
uv pip compile requirements-dev.in -o requirements-dev.txt
```

## Quick start

```bash
cp stellargate.example.yaml stellargate.yaml
# edit paths / base_url for your project
stellargate run --config stellargate.yaml --json-report report.json
```

Exit code is `0` if every enabled tool's findings stay below the configured
`fail_on` threshold, `1` otherwise — drop it into any CI step.

## Run tests

```bash
pip install -r requirements-dev.txt
pip install -e .
pytest
```

## Adding a new tool adapter

Every adapter implements one function:

```python
def run(options: dict) -> list[Finding]:
    ...
```

See `stellargate/adapters/rytscan.py` for a working example, or
`stellargate/adapters/shieldscan.py` for the Phase 2 stub pattern.
