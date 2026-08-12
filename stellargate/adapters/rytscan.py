"""Adapter for RytScan (Soroban contract static analysis).

Upstream: https://github.com/BreachDirect/RytScan
Invocation: cargo run -p rytscan-cli -- scan <path> --format json --fail-on <level>

RytScan's own rule IDs (AUTH-001, PANIC-*, TOKEN-*, EVENT-001, TTL-*, STORE-*)
are passed straight through as our rule_id — no remapping needed, they're
already namespaced and human-readable.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from stellargate.schema import AdapterError, Finding

TOOL_NAME = "rytscan"

CACHE_VERSION = 1
DEFAULT_CACHE_FILE = ".stellargate/rytscan-cache.json"


def run(options: dict) -> list[Finding]:
    path = options.get("path", ".")
    cache_file = _resolve_cache_file(options)

    # Cache lookup: only trust the cache when we can fully enumerate the files
    # the tool would scan AND every one of their content hashes matches the
    # previous run. A mismatch (file changed, file added/removed, cache absent)
    # falls through to a real CLI scan.
    hashes = _current_hashes(path)
    if hashes is not None:
        cache = _load_cache(cache_file)
        entry = cache.get("entries", {}).get(_entry_key(path))
        if entry is not None and entry.get("files") == hashes:
            return _replay(entry.get("findings", []))

    findings = _scan_cli(path)

    # Persist the fresh result keyed by per-file content hash so the next run
    # can skip the CLI entirely if nothing changed.
    if hashes is not None:
        cache = _load_cache(cache_file)
        cache.setdefault("entries", {})[_entry_key(path)] = {
            "files": hashes,
            "findings": [f.to_dict() for f in findings],
        }
        _save_cache(cache_file, cache)

    return findings


def _scan_cli(path: str) -> list[Finding]:
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


# --------------------------------------------------------------------------
# Content-hash caching
# --------------------------------------------------------------------------


def _resolve_cache_file(options: dict) -> Path:
    override = options.get("cache_file")
    if override:
        return Path(override)
    return Path(DEFAULT_CACHE_FILE)


def _entry_key(path: str) -> str:
    return str(Path(path).resolve())


def _current_hashes(path: str) -> dict[str, str] | None:
    """Map each scanned file to its sha256 content hash.

    Returns None when the path is unusable or contains no contract files, in
    which case caching is skipped entirely (always a real scan, preserving the
    original error semantics)."""
    files = _collect_files(path)
    if not files:
        return None
    hashes: dict[str, str] = {}
    for f in files:
        try:
            hashes[str(Path(f).resolve())] = hashlib.sha256(Path(f).read_bytes()).hexdigest()
        except OSError:
            return None
    return hashes


def _collect_files(path: str) -> list[str]:
    p = Path(path)
    if p.is_file():
        return [str(p.resolve())]
    if p.is_dir():
        return [str(f.resolve()) for f in p.rglob("*") if f.is_file() and f.suffix == ".rs"]
    return []


def _load_cache(path: Path) -> dict:
    """Corrupt or unreadable cache is treated as empty — never crash the scan."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _save_cache(path: Path, cache: dict) -> None:
    """Persistence is best-effort: a failure to write the cache must never fail
    the scan itself."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(cache, indent=2))
    except OSError:
        pass


def _replay(recorded: list[dict]) -> list[Finding]:
    return [Finding(**f) for f in recorded]


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
