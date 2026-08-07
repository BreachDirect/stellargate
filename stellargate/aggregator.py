"""Runs enabled adapters and collects all findings."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable

from stellargate.adapters import rytscan, schemalock, shieldscan, vaultsweep
from stellargate.config import Config
from stellargate.schema import AdapterError, Finding

ADAPTERS = {
    "rytscan": rytscan,
    "schemalock": schemalock,
    "vaultsweep": vaultsweep,
    "shieldscan": shieldscan,
}


class ToolRunResult:
    def __init__(self, tool: str, findings: list[Finding] | None, error: str | None):
        self.tool = tool
        self.findings = findings or []
        self.error = error


def _run_one(name: str, run: Callable[[dict], list[Finding]], options: dict) -> ToolRunResult:
    """Run a single adapter, mapping any failure onto a ToolRunResult error
    entry so one bad adapter never aborts the run."""
    try:
        findings = run(options)
        return ToolRunResult(name, findings, None)
    except AdapterError as e:
        return ToolRunResult(name, None, str(e))
    except Exception as e:
        # An adapter bug or unforeseen tool-output shape must not take
        # down the whole run — every other tool's findings still belong
        # in the report. Surface this as a clearly-labeled tool error
        # rather than crashing.
        return ToolRunResult(
            name, None, f"unexpected adapter error: {type(e).__name__}: {e}"
        )


def run_all(config: Config) -> list[ToolRunResult]:
    """Run every enabled tool. A single tool erroring does not stop the others —
    we want a partial report rather than an all-or-nothing failure.

    Adapters are IO/subprocess-bound and CPU-light, so they run concurrently in
    a thread pool rather than a process pool. Worker count equals the number of
    enabled adapters — only four tools are known, so one thread per enabled
    adapter is trivially small and keeps wall-clock time near the slowest
    adapter instead of the sum. Futures are collected in config order, so the
    report never reorders tools.
    """
    enabled = [(name, tool_cfg) for name, tool_cfg in config.tools.items() if tool_cfg.enabled]
    if not enabled:
        return []

    with ThreadPoolExecutor(max_workers=len(enabled)) as pool:
        futures = [
            pool.submit(_run_one, name, ADAPTERS[name].run, tool_cfg.options)
            for name, tool_cfg in enabled
        ]
        return [f.result() for f in futures]


def all_findings(results: list[ToolRunResult]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        findings.extend(r.findings)
    return sorted(findings, key=lambda f: -f.severity_rank)
