"""Runs enabled adapters and collects all findings."""

from __future__ import annotations

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


def run_all(config: Config) -> list[ToolRunResult]:
    """Run every enabled tool. A single tool erroring does not stop the others —
    we want a partial report rather than an all-or-nothing failure."""
    results: list[ToolRunResult] = []
    for name, tool_config in config.tools.items():
        if not tool_config.enabled:
            continue
        adapter = ADAPTERS[name]
        try:
            findings = adapter.run(tool_config.options)
            results.append(ToolRunResult(name, findings, None))
        except AdapterError as e:
            results.append(ToolRunResult(name, None, str(e)))
        except Exception as e:  # noqa: BLE001 - a buggy adapter must surface, not crash the run
            # An adapter bug or unforeseen tool-output shape must not take
            # down the whole run — every other tool's findings still belong
            # in the report. Surface this as a clearly-labeled tool error
            # rather than crashing.
            results.append(
                ToolRunResult(name, None, f"unexpected adapter error: {type(e).__name__}: {e}")
            )
    return results


def all_findings(results: list[ToolRunResult]) -> list[Finding]:
    findings: list[Finding] = []
    for r in results:
        findings.extend(r.findings)
    return sorted(findings, key=lambda f: -f.severity_rank)
