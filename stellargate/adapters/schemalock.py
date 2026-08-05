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


def _resolve_base_urls(options: dict) -> dict[str, str]:
    """Resolve configured base URLs into an {env_label: url} mapping.

    Accepts three shapes (last one wins if several are present):
      * options["base_urls"] as a dict {"env": "url"}  -> labels are the env keys
      * options["base_urls"] as a list of url strings   -> labels are the URLs
      * options["base_url"] as a single url string        -> legacy, label defaults to url
    """
    urls = options.get("base_urls")
    if isinstance(urls, dict):
        return {str(label): str(url) for label, url in urls.items()}
    if isinstance(urls, (list, tuple)):
        return {str(url): str(url) for url in urls}
    single = options.get("base_url")
    return {str(single): str(single) for single in [single]}


def _run_one(config_path: str, base_url: str) -> dict:
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

        try:
            with open(report_path) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise AdapterError(f"{TOOL_NAME}: report file was not valid JSON ({e})")


def run(options: dict) -> list[Finding]:
    config_path = options.get("config")
    if not config_path:
        raise AdapterError(f"{TOOL_NAME}: 'config' option (path to schemalock.yaml) is required")

    environments = _resolve_base_urls(options)

    findings: list[Finding] = []
    for label, url in environments.items():
        data = _run_one(config_path, url)
        for finding in parse_report(data):
            # Prepend the environment label so a reviewer can tell which
            # environment a contract check failed against, e.g.
            # "staging: GET /escrows/{id}". The legacy single-URL path uses
            # a URL label, keeping the finding self-describing but unchanged
            # in shape.
            if label:
                finding.location = f"{label}: {finding.location}" if finding.location else label
            findings.append(finding)
    return findings


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
