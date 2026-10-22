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

## Editor configuration assistance

The [JSON Schema](stellargate.schema.json) describes `stellargate.yaml` for
editor completion and structural validation. The example already includes a
YAML language-server directive. If your config lives elsewhere, point it at
the schema's actual relative path or the upstream URL:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/BreachDirect/stellargate/main/stellargate.schema.json
```

With the VS Code YAML extension, opening the example offers known tool names,
options and value types. Unknown tool names and configurations without an
explicitly enabled tool are rejected. `fail_on` is case insensitive, as in the
loader. Extra top-level and adapter options remain allowed because the loader
allows them; this is not a strict typo checker for every option.

Use YAML booleans (`true`/`false`), not strings such as `"false"`; the schema
rejects strings even though the loader currently coerces them with `bool()`.
Editor validation does not replace a run: it cannot check that a file exists,
that a service is reachable, or that tools are installed. SchemaLock needs its
`config` path when invoked; ShieldScan remains an unimplemented Phase 2 adapter.
No schema validation dependency is added to the CLI's runtime.

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
