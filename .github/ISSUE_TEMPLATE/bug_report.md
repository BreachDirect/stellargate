---
name: Bug report
about: Report a bug in StellarGate so we can fix it
title: "[BUG] "
labels: ["bug"]
assignees: []
---

## Description

A clear and concise description of the bug.

## Environment

- **OS:** (e.g. macOS 14, Ubuntu 22.04, Windows 11)
- **Python version:** (e.g. 3.11.4 — StellarGate requires >= 3.10)
- **StellarGate version / commit:** (e.g. 0.1.0 or a specific commit SHA)

## Reproduction steps

1. Config: paste or describe your `stellargate.yaml` (feel free to redact
   secrets/URLs).
2. Command run, e.g.:
   ```bash
   stellargate run --config stellargate.yaml --fail-on high
   ```
3. ...

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened, including the **exit code** (refer to the exit-code
semantics below).

## Logs / output

Paste any relevant stderr/stdout, JSON or Markdown report excerpts, and tool
adapter messages. If the bug is a crash, include the full traceback.

## Which adapter(s) are involved?

- [ ] RytScan (Soroban contract scan)
- [ ] SchemaLock (API contract lock)
- [ ] VaultSweep (secrets scan)
- [ ] Not sure / core orchestrator / config / reporting

If adapter-specific, note the exact adapter error message, e.g.
`rytscan: scan failed (exit code N), no output produced`.

## Config help (already read)

- `target`, `fail_on` (`critical | high | medium | low`), per-tool
  `enabled`, `path`/`config`/`base_url` are documented in
  `stellargate.example.yaml`.
- `--config` overrides the default config path; `--fail-on` overrides the
  configured threshold from the CLI.

## Exit-code semantics reminder

- `0`: every enabled tool's findings stayed below the configured `fail_on`
  threshold (gate passed).
- `1`: at least one finding met or exceeded the threshold (gate failed) —
  this is the expected CI-blocking result and is **not** a bug by itself.
- If a subprocess parse error or unexpected adapter failure crashes the run,
  report that as a bug here.

## Additional context

Any other relevant details, logs, or screenshots.