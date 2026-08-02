"""Adapter for SchemaLock (API contract test harness).

Upstream: https://github.com/BreachDirect/schemalock
Invocation: schemalock test --config <path> --base-url <url> --json-report <tmpfile>
Exit code: 0 if all checks pass, 1 otherwise.

SchemaLock reports *passed/failed checks*, not "findings" in the
vulnerability-scanner sense — we only surface FAILED checks as Findings,
since a passing contract check isn't something a reviewer needs to see in
a compliance report.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from stellargate.schema import AdapterError, Finding

TOOL_NAME = "schemalock"

# SchemaLock doesn't emit its own severity per check; we map by failure
# type since an auth-bypass is categorically worse than a status-code drift.
FAILURE_SEVERITY = {
    "auth_required": "critical",   # silent auth bypass
    "error_envelope": "medium",    # response shape drift
    "status": "high",              # wrong status code (e.g. leaks existence)
}
DEFAULT_SEVERITY = "medium"


def run(options: dict) -> list[Finding]:
    config_path = options.get("config")
    if not config_path:
        raise AdapterError(f"{TOOL_NAME}: 'config' option (path to schemalock.yaml) is required")
    base_url = options.get("base_url", "http://127.0.0.1:8000")

    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "schemalock-report.json"
        cmd = [
            "schemalock", "test",
            "--config", config_path,
            "--base-url", base_url,
            "--json-report", str(report_path),
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except FileNotFoundError as e:
            raise AdapterError(f"{TOOL_NAME}: 'schemalock' CLI not found ({e})")
        except subprocess.TimeoutExpired:
            raise AdapterError(f"{TOOL_NAME}: test run timed out after 120s")

        if not report_path.exists():
            raise AdapterError(f"{TOOL_NAME}: no report produced at {report_path}")

        with open(report_path) as f:
            data = json.load(f)

    return parse_report(data)


def parse_report(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    checks = data.get("checks", [])
    for check in checks:
        if check.get("passed", True):
            continue
        check_type = check.get("check_type", check.get("type", "unknown"))
        findings.append(
            Finding(
                tool=TOOL_NAME,
                rule_id=f"CONTRACT-{check_type.upper()}",
                severity=FAILURE_SEVERITY.get(check_type, DEFAULT_SEVERITY),
                message=check.get("detail", check.get("message", "contract check failed")),
                location=check.get("endpoint", check.get("name")),
                raw=check,
            )
        )
    return findings
