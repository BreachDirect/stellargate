"""JSON and Markdown compliance report generation."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from stellargate.aggregator import ToolRunResult
from stellargate.schema import SEVERITY_ORDER, Finding


def finding_key(finding: "Finding | dict[str, Any]") -> tuple:
    """Uniqueness key for a finding: (tool, rule_id, location).

    Accepts either a live Finding object or a dict as produced by
    Finding.to_dict() (i.e. entries inside the JSON report's "findings"
    list), so the same key works for diffing current results against a
    previously serialized baseline report.
    """
    if isinstance(finding, Finding):
        return (finding.tool, finding.rule_id, finding.location)
    return (finding["tool"], finding["rule_id"], finding.get("location"))


def diff_findings(
    current: list[Finding], baseline_report: dict[str, Any]
) -> list[Finding]:
    """Return only findings newly introduced since a baseline report.

    A finding is considered pre-existing if its (tool, rule_id, location)
    key already appears in the baseline report's "findings" list. Only
    brand-new findings are returned — this is what makes gating on
    regressions possible without penalizing every historical finding.
    """
    baseline_keys = {finding_key(f) for f in baseline_report.get("findings", [])}
    return [f for f in current if finding_key(f) not in baseline_keys]


def to_json(
    results: list[ToolRunResult],
    fail_on: str,
    gate_passed: bool,
    diff_mode: bool = False,
) -> dict:
    findings = [f for r in results for f in r.findings]
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fail_on": fail_on,
        "diff": bool(diff_mode),
        "passed": gate_passed,
        "summary": counts,
        "tools": [
            {
                "tool": r.tool,
                "error": r.error,
                "finding_count": len(r.findings),
            }
            for r in results
        ],
        "findings": [f.to_dict() for f in findings],
    }


def to_markdown(
    results: list[ToolRunResult],
    fail_on: str,
    gate_passed: bool,
    diff_mode: bool = False,
) -> str:
    findings = [f for r in results for f in r.findings]
    lines: list[str] = []

    status = "✅ PASSED" if gate_passed else "❌ FAILED"
    mode_label = " — diff mode (only new findings vs baseline)" if diff_mode else ""
    lines.append(f"# StellarGate Compliance Report — {status}{mode_label}\n")
    lines.append(f"Threshold: fail on **{fail_on}** or above.\n")

    lines.append("## Per-tool summary\n")
    lines.append("| Tool | Status | Findings |")
    lines.append("|---|---|---|")
    for r in results:
        if r.error:
            lines.append(f"| {r.tool} | ⚠️ error | — |")
        else:
            lines.append(f"| {r.tool} | ok | {len(r.findings)} |")
    lines.append("")

    errored = [r for r in results if r.error]
    if errored:
        lines.append("## Tool errors\n")
        for r in errored:
            lines.append(f"- **{r.tool}**: {r.error}")
        lines.append("")

    if findings:
        lines.append("## Findings\n")
        lines.append("| Severity | Tool | Rule | Location | Message |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            loc = f.location or "—"
            lines.append(
                f"| {f.severity.upper()} | {f.tool} | {f.rule_id} | {loc} | {f.message} |"
            )
    else:
        lines.append("No findings. Clean run.")

    return "\n".join(lines)


def gate_passed(findings: list[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return not any(f.severity_rank >= threshold for f in findings)
