"""Adapter for VaultSweep (secrets/credential scanner).

Upstream: https://github.com/BreachDirect/vaultsweep
Invocation: vaultsweep scan <path> --format json --fail-on <level>

Rule IDs (STELLAR-001, MNEMONIC-001, API-00x, DEFAULT-001, RPC-001) are
already well-namespaced and pass through unchanged.
"""
from __future__ import annotations

import fnmatch
import json
import re
import subprocess

from stellargate.schema import AdapterError, Finding

TOOL_NAME = "vaultsweep"

_FILE_LINE_RE = re.compile(r":\d+(?::\d+)?$")


def _is_ignored(location: str | None, patterns: list[str]) -> bool:
    if not location or not patterns:
        return False
    # VaultSweep locations carry a ":line" (and optionally ":col") suffix, which
    # would break glob suffixes like "**/*.example". Strip that suffix for the
    # path match, but keep matching the raw location too in case it has none.
    path = _FILE_LINE_RE.sub("", location)
    candidates = {path}
    if path != location:
        candidates.add(location)
    # fnmatchcase (not fnmatch: it does no normcase, so it never silently
    # rewrites path separators on Windows; locations are matched as-is.
    return any(fnmatch.fnmatchcase(cand_loc, pat) for cand_loc in candidates for pat in patterns)


def run(options: dict) -> list[Finding]:
    path = options.get("path", ".")
    cmd = ["vaultsweep", "scan", path, "--format", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except FileNotFoundError as e:
        raise AdapterError(f"{TOOL_NAME}: 'vaultsweep' CLI not found ({e})")
    except subprocess.TimeoutExpired:
        raise AdapterError(f"{TOOL_NAME}: scan timed out after 180s")

    # Same principle as rytscan: a crashed scan with no output must never be
    # read as "zero findings" — that would be a false clean bill of health.
    if result.returncode != 0 and not result.stdout.strip():
        raise AdapterError(
            f"{TOOL_NAME}: scan failed (exit code {result.returncode}), no output produced. "
            f"stderr: {result.stderr.strip()[:500]}"
        )

    findings = parse_output(result.stdout)

    ignore_paths = options.get("ignore_paths") or []
    if ignore_paths:
        findings = [f for f in findings if not _is_ignored(f.location, ignore_paths)]

    return findings


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
