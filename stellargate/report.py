"""JSON and Markdown compliance report generation."""
from __future__ import annotations

from datetime import datetime, timezone

from stellargate.aggregator import ToolRunResult
from stellargate.schema import SEVERITY_ORDER, Finding


def to_json(results: list[ToolRunResult], fail_on: str, gate_passed: bool) -> dict:
    findings = [f for r in results for f in r.findings]
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fail_on": fail_on,
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
    group_by: str = "severity",
) -> str:
    if group_by not in ("severity", "tool"):
        raise ValueError(f"Invalid group_by '{group_by}'; must be 'severity' or 'tool'")

    findings = [f for r in results for f in r.findings]
    lines: list[str] = []

    status = "✅ PASSED" if gate_passed else "❌ FAILED"
    lines.append(f"# StellarGate Compliance Report — {status}\n")
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

    if findings or group_by == "tool":
        if group_by == "severity":
            lines.append("## Findings\n")
            lines.append("| Severity | Tool | Rule | Location | Message |")
            lines.append("|---|---|---|---|---|")
            for f in findings:
                loc = f.location or "—"
                lines.append(
                    f"| {f.severity.upper()} | {f.tool} | {f.rule_id} | {loc} | {f.message} |"
                )
        else:
            lines.append("## Findings\n")
            for r in results:
                if r.error:
                    continue
                lines.append(f"### {r.tool}\n")
                if r.findings:
                    lines.append("| Severity | Rule | Location | Message |")
                    lines.append("|---|---|---|---|")
                    for f in sorted(r.findings, key=lambda x: -x.severity_rank):
                        loc = f.location or "—"
                        lines.append(
                            f"| {f.severity.upper()} | {f.rule_id} | {loc} | {f.message} |"
                        )
                else:
                    lines.append("No findings. Clean run.")
                lines.append("")
    else:
        lines.append("No findings. Clean run.")

    return "\n".join(lines)


def gate_passed(findings: list[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return not any(f.severity_rank >= threshold for f in findings)
