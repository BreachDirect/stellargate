---
name: Feature request
about: Suggest an idea for StellarGate
title: "[FEATURE: ...]"
labels: [enhancement]
assignees: []
---

# Feature request

## Problem / motivation

What problem are you solving? Why is the current behaviour (or lack of it) a
pain point? Context is especially valuable here — e.g. a CI workflow that is
hard to wire up, an adapter gap, or a report-format need.

## Proposed behaviour

Describe the desired behaviour as concretely as possible. Where relevant,
show example config (`stellargate.yaml`), CLI usage, or an example excerpt of
the JSON / Markdown report you'd like.

## Alternatives considered

- Alternative 1 — what it is and its trade-offs
- Alternative 2 — what it is and its trade-offs

## Impact / scope

- Which components does this touch?
  - `stellargate/adapters/` (rytscan, schemalock, vaultsweep, shieldscan — the
    latter is a Phase 2 stub)
  - core orchestrator / aggregation (`aggregator.py`)
  - reporting (`report.py` / `cli.py`)
  - config (`config.py`)
- Does it need a config schema change (`stellargate.example.yaml`)?
- Does it affect the `--config` invocation or exit-code semantics?

## Extra context

Any additional context: linked issues, PR, upstream tool changes, wireframes,
or screenshots.