"""Adapter for VaultSweep (secrets/credential scanner).

Upstream: https://github.com/BreachDirect/vaultsweep
Invocation: vaultsweep scan <path> --format json --fail-on <level>

Rule IDs (STELLAR-001, MNEMONIC-001, API-00x, DEFAULT-001, RPC-001) are
already well-namespaced and pass through unchanged.
"""
from __future__ import annotations

import json
import subprocess

from stellargate.schema import AdapterError, Finding

TOOL_NAME = "vaultsweep"


def run(options: dict) -> list[Finding]:
    path = options.get("path", ".")
    cmd = ["vaultsweep", "scan", path, "--format", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except FileNotFoundError as e:
        raise AdapterError(f"{TOOL_NAME}: 'vaultsweep' CLI not found ({e})")
    except subprocess.TimeoutExpired:
        raise AdapterError(f"{TOOL_NAME}: scan timed out after 180s")

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
                severity=item.get("severity", "high"),
                message=item.get("message", item.get("description", "")),
                location=item.get("file", item.get("location")),
                raw=item,
            )
        )
    return findings
