"""Adapter for RytScan (Soroban contract static analysis).

Upstream: https://github.com/BreachDirect/RytScan
Invocation: cargo run -p rytscan-cli -- scan <path> --format json --fail-on <level>

RytScan's own rule IDs (AUTH-001, PANIC-*, TOKEN-*, EVENT-001, TTL-*, STORE-*)
are passed straight through as our rule_id — no remapping needed, they're
already namespaced and human-readable.
"""

from __future__ import annotations

import json
import subprocess

from stellargate.schema import AdapterError, Finding

TOOL_NAME = "rytscan"


def run(options: dict) -> list[Finding]:
    path = options.get("path", ".")
    cmd = [
        "cargo",
        "run",
        "-p",
        "rytscan-cli",
        "--",
        "scan",
        path,
        "--format",
        "json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    except FileNotFoundError as e:
        raise AdapterError(
            f"{TOOL_NAME}: 'cargo' not found — is the Rust toolchain installed? ({e})"
        )
    except subprocess.TimeoutExpired:
        raise AdapterError(f"{TOOL_NAME}: scan timed out after 300s")

    # IMPORTANT: a nonzero exit with no stdout means the tool failed to run
    # (bad path, build error, crash) — that must surface as an adapter error,
    # never as "zero findings". Silently treating a failed scan as a clean
    # pass would defeat the purpose of a security gate.
    if result.returncode != 0 and not result.stdout.strip():
        raise AdapterError(
            f"{TOOL_NAME}: scan failed (exit code {result.returncode}), no output produced. "
            f"stderr: {result.stderr.strip()[:500]}"
        )

    return parse_output(result.stdout)


def parse_output(stdout: str) -> list[Finding]:
    if not stdout.strip():
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        raise AdapterError(f"{TOOL_NAME}: could not parse JSON output ({e})")

    findings: list[Finding] = []
    for item in data.get("findings", data if isinstance(data, list) else []):
        findings.append(
            Finding(
                tool=TOOL_NAME,
                rule_id=item.get("rule_id", item.get("rule", "UNKNOWN")),
                severity=item.get("severity", "medium"),
                message=item.get("message", item.get("description", "")),
                location=item.get("location", item.get("file")),
                raw=item,
            )
        )
    return findings
