"""JSON, Markdown, and HTML compliance report generation."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

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


def to_html(results: list[ToolRunResult], fail_on: str, gate_passed: bool) -> str:
    """Render a self-contained styled HTML report (no external CSS/JS)."""
    findings = [f for r in results for f in r.findings]
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1

    status = "PASSED" if gate_passed else "FAILED"
    status_class = "pass" if gate_passed else "fail"
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    tool_rows = []
    for r in results:
        if r.error:
            tool_rows.append(
                f"<tr><td>{escape(r.tool)}</td>"
                '<td class="error">&#9888; error</td><td>&mdash;</td></tr>'
            )
        else:
            tool_rows.append(
                f"<tr><td>{escape(r.tool)}</td>"
                f'<td class="ok">ok</td><td>{len(r.findings)}</td></tr>'
            )

    error_rows = [
        f"<li><strong>{escape(r.tool)}</strong>: {escape(r.error)}</li>"
        for r in results
        if r.error
    ]

    finding_rows = [
        (
            "<tr>"
            f"<td><span class=\"sev sev-{escape(f.severity)}\">{escape(f.severity)}</span></td>"
            f"<td>{escape(f.tool)}</td>"
            f"<td>{escape(f.rule_id)}</td>"
            f"<td>{escape(f.location) if f.location else '&mdash;'}</td>"
            f"<td>{escape(f.message)}</td>"
            "</tr>"
        )
        for f in findings
    ]

    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        "<title>StellarGate Compliance Report</title>",
        "<style>",
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,"
        "Helvetica,Arial,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;"
        "color:#1f2328;line-height:1.5}",
        "h1{font-size:1.5rem}.badge{display:inline-block;padding:.3rem .8rem;"
        "border-radius:4px;color:#fff;font-weight:600}",
        ".badge.pass{background:#1a7f37}.badge.fail{background:#cf222e}",
        "table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}",
        "th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;font-size:.9rem}",
        "th{background:#f6f8fa}td.ok{color:#1a7f37}td.error{color:#cf222e}",
        ".sev{padding:.1rem .4rem;border-radius:3px;color:#fff;font-size:.8rem}",
        ".sev-critical{background:#cf222e}.sev-high{background:#bc4c00}",
        ".sev-medium{background:#9a6700}.sev-low{background:#57606a}",
        "ul.errors{color:#cf222e}code{background:#f6f8fa;padding:.1rem .3rem;"
        "border-radius:3px}",
        "</style>",
        "</head>",
        "<body>",
        f"<h1>StellarGate Compliance Report &mdash; "
        f'<span class="badge {status_class}">{status}</span></h1>',
        f"<p>Threshold: fail on <strong>{escape(fail_on)}</strong> or above. "
        f"Generated at <code>{escape(generated_at)}</code>.</p>",
        f'<h2>Per-tool summary <span style="font-weight:normal;font-size:.9rem">'
        f"(critical {counts['critical']}, high {counts['high']}, "
        f"medium {counts['medium']}, low {counts['low']})</span></h2>",
        "<table><thead><tr><th>Tool</th><th>Status</th><th>Findings</th></tr></thead>",
        "<tbody>",
        *tool_rows,
        "</tbody></table>",
    ]

    if error_rows:
        parts.append('<h2>Tool errors</h2><ul class="errors">')
        parts.extend(error_rows)
        parts.append("</ul>")

    if findings:
        parts.append("<h2>Findings</h2>")
        parts.append(
            "<table><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th>"
            "<th>Location</th><th>Message</th></tr></thead><tbody>"
        )
        parts.extend(finding_rows)
        parts.append("</tbody></table>")
    else:
        parts.append("<p>No findings. Clean run.</p>")

    parts.append("</body></html>")
    return "\n".join(parts)


def gate_passed(findings: list[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return not any(f.severity_rank >= threshold for f in findings)
