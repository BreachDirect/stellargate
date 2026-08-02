# Architecture — StellarGate

## Overview

StellarGate is a Python CLI that shells out to each underlying tool's own
CLI, parses/normalizes their output into one schema, aggregates, and
renders a report. It does not reimplement any detector.

```
stellargate.yaml
      │
      ▼
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│   Config    │────▶│  Adapters    │────▶│  Aggregator   │
│   loader    │     │ (subprocess) │     │ (unified      │
└─────────────┘     └──────────────┘     │  findings)    │
                                          └───────┬───────┘
                                                  ▼
                                          ┌───────────────┐
                                          │ Report writer │
                                          │ (JSON + MD)   │
                                          └───────┬───────┘
                                                  ▼
                                          exit code (0/1)
```

## Components

### `stellargate/config.py`
Loads and validates `stellargate.yaml`. Schema:

```yaml
target: ./my-repo
fail_on: high          # critical | high | medium | low
tools:
  rytscan:
    enabled: true
    path: ./contracts
  schemalock:
    enabled: true
    config: ./schemalock.yaml
    base_url: http://127.0.0.1:8000
  vaultsweep:
    enabled: true
    path: .
  shieldscan:
    enabled: false      # Phase 2 — adapter not built yet
```

### `stellargate/schema.py`
The one normalized shape every adapter must produce:

```python
Finding = {
    "tool": str,           # "rytscan" | "schemalock" | "vaultsweep" | "shieldscan"
    "rule_id": str,        # e.g. "AUTH-001", "STELLAR-001"
    "severity": str,       # "critical" | "high" | "medium" | "low"
    "message": str,
    "location": str | None,  # file:line, endpoint name, or URL depending on tool
    "raw": dict,           # original tool output, preserved for debugging
}
```

### `stellargate/adapters/`
One module per tool. Each adapter:
1. Builds the subprocess command from config
2. Runs it, captures stdout (JSON) and exit code
3. Parses tool-specific JSON into `Finding` objects
4. Never raises on a *scan* finding something — only raises on adapter
   failure (tool not installed, malformed output, etc.)

- `rytscan.py` — invokes `cargo run -p rytscan-cli -- scan <path> --format json`
- `schemalock.py` — invokes `schemalock test --config <path> --base-url <url> --json-report <tmpfile>`, reads `<tmpfile>`
- `vaultsweep.py` — invokes `vaultsweep scan <path> --format json`
- `shieldscan.py` — **Phase 2.** Stub raises `NotImplementedError` with a
  clear message; config defaults to `enabled: false`.

### `stellargate/aggregator.py`
Runs enabled adapters (sequentially in Phase 1; parallelizable later),
collects all `Finding` lists into one, sorts by severity.

### `stellargate/report.py`
- `to_json(findings) -> dict` — machine-readable, for the `--json-report` flag
- `to_markdown(findings) -> str` — human-readable, per-tool summary table +
  full findings table, for CI comment posting in Phase 2

### `stellargate/cli.py`
Entrypoint: `stellargate run --config stellargate.yaml [--json-report path] [--fail-on LEVEL]`.
Exit code: `1` if any finding's severity >= configured threshold, else `0`.

## Adapter contract (why this is safe to extend)

Every adapter implements one function:

```python
def run(config: dict) -> list[Finding]:
    ...
```

Adding ShieldScan in Phase 2 means writing `shieldscan.py` against this
same contract — nothing else in the system changes. This is the whole
point of the orchestrator pattern: new tools are additive, not invasive.

## Testing strategy (Phase 1)

Real subprocess calls to the four external tools are **not** mocked away —
but since CI environments won't always have all four toolchains installed,
adapters are tested two ways:

1. **Unit tests** — subprocess calls are mocked with `unittest.mock`,
   feeding each adapter realistic captured JSON (fixtures in
   `tests/fixtures/`) to verify parsing logic.
2. **Integration smoke test** (optional, run manually / in a fuller CI
   later) — actually invokes the tools against their own bundled example
   fixtures, if the toolchain is present.

## Known limitations at end of Phase 1

- ShieldScan is not integrated (no clean CLI/JSON mode upstream yet — see
  Phase 2 issue).
- No GitHub Action yet — `stellargate run` is a local/manual CLI at the
  end of Phase 1.
- Adapters run sequentially, not in parallel (fine for Phase 1 scale).
