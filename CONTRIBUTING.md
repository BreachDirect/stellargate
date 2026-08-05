# Contributing to StellarGate

Thanks for helping out. StellarGate is a small Python CLI that runs your
Stellar Wave security tools (RytScan, SchemaLock, VaultSweep) behind one
command and turns their output into a single compliance report and pass/fail
exit code.

Read first:

- `README.md` — what it does and how to run it
- `PRD.md` — the product goal and scope
- `architecture.md` — how the pieces fit together

## Development setup

Requires Python 3.10+.

```bash
pip install -e ".[dev]"
```

This installs the package in editable mode plus the dev dependencies
(`pytest`). There is no other toolchain required.

## Running tests

```bash
pytest
```

Tests live in `tests/` and run against fixture files in `tests/fixtures/`:

- `test_adapters.py` — parsing and error handling for the RytScan,
  SchemaLock, and VaultSweep adapters (mocked subprocess calls)
- `test_aggregator_and_report.py` — aggregation, severity sorting, pass/fail
  gating, and JSON + Markdown report output

If you touch parsing, aggregation, or reporting, run the full suite. A change
that breaks `pytest` won't be merged.

## Submitting a pull request

1. Fork the repo and create a branch off `main`, named for the issue you're
   fixing, e.g. `20260806-contributing`.
2. Keep the change small — one issue, one PR. If a fix touches more than one
   thing, split it into separate PRs.
3. Follow the existing commit style: a concise subject line that states the
   change, optionally with a short body of specifics. Existing history is the
   model — no prefixes or tooling conventions to match beyond that.
4. Add or update tests for any new feature or bug fix, and prove they pass
   (`pytest`).
5. Reference the issue in the PR description with `Fixes #N` so it links and
   closes on merge.
6. Keep the PR focused: no unrelated reformatting, renames, or doc churn in a
   code PR.

## Code style

Small and direct. One adapter implements one `run(options: dict)` function;
one module does one job. Readable beats clever.

- Follow the shape of the existing code — type the signatures, keep the
  docstrings short, keep functions small.
- No formatting or linting tools are configured, so match the existing style
  by eye rather than adding a new toolchain.
- Preserve the failure semantics: a scan that crashes must raise an adapter
  error, never look like a clean pass. See the regression tests in
  `test_adapters.py`.

Questions? Open an issue instead of guessing.
