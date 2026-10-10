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


SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def to_sarif(results: list[ToolRunResult], fail_on: str, gate_passed: bool) -> dict:
    findings = [f for r in results for f in r.findings]

    rules = {}
    for f in findings:
        if f.rule_id in rules:
            continue
        rules[f.rule_id] = {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {
                "text": f"{f.tool}: {f.message}",
            },
        }

    sarif_results = []
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": SEVERITY_TO_LEVEL[f.severity],
            "message": {"text": f.message},
        }
        if f.location:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location},
                    }
                }
            ]
        sarif_results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": "stellargate",
                "version": "0.1.0",
                "informationUri": "https://github.com/BreachDirect/stellargate",
            }
        },
        "results": sarif_results,
    }
    if rules:
        run["tool"]["driver"]["rules"] = list(rules.values())

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def to_markdown(results: list[ToolRunResult], fail_on: str, gate_passed: bool) -> str:
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
