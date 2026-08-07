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
import time
from pathlib import Path

from stellargate.schema import AdapterError, Finding

TOOL_NAME = "schemalock"

# Target server may still be warming up (e.g. connection-refused on the very
# first contract probe). Give it one short grace window before giving up.
RETRY_DELAY_SECONDS = 5
SCHEMALOCK_TIMEOUT_SECONDS = 120

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
        last_stderr = ""
        for attempt in range(2):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCHEMALOCK_TIMEOUT_SECONDS)
            except FileNotFoundError as e:
                # Retrying cannot help a missing binary — fail fast.
                raise AdapterError(f"{TOOL_NAME}: 'schemalock' CLI not found ({e})")
            except subprocess.TimeoutExpired:
                # Same for a hang — the report will never arrive.
                raise AdapterError(f"{TOOL_NAME}: test run timed out after {SCHEMALOCK_TIMEOUT_SECONDS}s")

            last_stderr = (proc.stderr or "").strip()
            if proc.returncode == 0 and report_path.exists():
                break
            if attempt == 0:
                time.sleep(RETRY_DELAY_SECONDS)

        if not report_path.exists():
            detail = f" (last run stderr: {last_stderr})" if last_stderr else ""
            raise AdapterError(f"{TOOL_NAME}: no report produced at {report_path}{detail}")

        try:
            with open(report_path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise AdapterError(f"{TOOL_NAME}: report file was not valid JSON ({e})")

    return parse_report(data)


def parse_report(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    checks = data.get("checks", [])
    for check in checks:
        if check.get("passed", True):
            continue
        # Normalize case before the severity lookup — an unnormalized
        # "Auth_Required" vs "auth_required" would silently miss the map
        # and fall back to DEFAULT_SEVERITY, downgrading a critical
        # auth-bypass finding to medium. Never let a formatting quirk
        # quietly reduce a finding's severity.
        check_type = check.get("check_type", check.get("type", "unknown")).lower()
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
