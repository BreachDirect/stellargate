import json
from pathlib import Path
from unittest.mock import patch

import pytest

from stellargate.adapters import rytscan, schemalock, vaultsweep
from stellargate.schema import AdapterError

FIXTURES = Path(__file__).parent / "fixtures"


def test_rytscan_parse_output():
    raw = (FIXTURES / "rytscan_output.json").read_text()
    findings = rytscan.parse_output(raw)
    assert len(findings) == 2
    assert findings[0].tool == "rytscan"
    assert findings[0].rule_id == "AUTH-001"
    assert findings[0].severity == "high"
    assert findings[0].location == "src/vault.rs:42"


def test_rytscan_parse_empty_output():
    assert rytscan.parse_output("") == []


def test_schemalock_only_surfaces_failed_checks():
    data = json.loads((FIXTURES / "schemalock_report.json").read_text())
    findings = schemalock.parse_report(data)
    # 3 checks in fixture, 1 passed (auth_required) -> only 2 findings
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"CONTRACT-STATUS", "CONTRACT-ERROR_ENVELOPE"}


def test_schemalock_auth_bypass_is_not_downgraded():
    # if an auth_required check itself failed, severity must be critical
    data = {
        "checks": [
            {
                "name": "auth_bypass_case",
                "check_type": "auth_required",
                "passed": False,
                "endpoint": "GET /escrows/{id}",
                "detail": "unauthenticated request returned 200 (auth bypass!)",
            }
        ]
    }
    findings = schemalock.parse_report(data)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_vaultsweep_parse_output():
    raw = (FIXTURES / "vaultsweep_output.json").read_text()
    findings = vaultsweep.parse_output(raw)
    assert len(findings) == 2
    assert findings[0].rule_id == "STELLAR-001"
    assert findings[0].severity == "critical"


def test_vaultsweep_ignore_paths_drops_matching_findings():
    stdout = json.dumps(
        {
            "findings": [
                {"rule_id": "STELLAR-001", "severity": "critical", "file": "tests/fixtures/keys.example:3"},
                {"rule_id": "RPC-001", "severity": "high", "file": "src/client.js:11"},
            ]
        }
    )
    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout=stdout, returncode=0)):
        findings = vaultsweep.run({"path": ".", "ignore_paths": ["tests/fixtures/**", "**/*.example"]})
    assert [f.rule_id for f in findings] == ["RPC-001"]


def test_vaultsweep_ignore_paths_keeps_non_matching_findings():
    stdout = json.dumps(
        {
            "findings": [
                {"rule_id": "STELLAR-001", "severity": "critical", "file": "src/main.py:7"},
                {"rule_id": "RPC-001", "severity": "high", "file": "src/client.js:11"},
            ]
        }
    )
    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout=stdout, returncode=0)):
        findings = vaultsweep.run({"path": ".", "ignore_paths": ["tests/fixtures/**", "**/*.example"]})
    assert [f.rule_id for f in findings] == ["STELLAR-001", "RPC-001"]


def test_vaultsweep_ignore_paths_absent_or_empty_keeps_everything():
    raw = (FIXTURES / "vaultsweep_output.json").read_text()
    for options in ({"path": "."}, {"path": ".", "ignore_paths": []}):
        with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout=raw, returncode=0)):
            findings = vaultsweep.run(options)
        assert len(findings) == 2
        assert findings == vaultsweep.parse_output(raw)


def test_vaultsweep_ignore_paths_matches_raw_line_suffixed_location():
    # "**/*.example" must match "config/.env.example:3" once the ":line"
    # suffix is stripped, even though the raw location is not a plain path.
    assert vaultsweep._is_ignored("config/.env.example:3", ["**/*.example"])
    assert not vaultsweep._is_ignored("src/client.js:11", ["**/*.example"])


class _FakeCompletedProcess:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


def test_rytscan_crash_with_no_output_raises_not_zero_findings():
    """Regression test: a tool that crashes (nonzero exit, empty stdout) must
    raise AdapterError, never be silently read as a clean 'zero findings' scan."""
    with (
        patch(
            "subprocess.run",
            return_value=_FakeCompletedProcess(
                stdout="", returncode=1, stderr="panic: build failed"
            ),
        ),
        pytest.raises(AdapterError, match="scan failed"),
    ):
        rytscan.run({"path": "./contracts"})


def test_rytscan_clean_pass_with_zero_findings_is_fine():
    """A genuine clean scan (exit 0, empty JSON findings list) is a legitimate pass —
    only a crash (nonzero exit + empty stdout) should raise."""
    with patch(
        "subprocess.run",
        return_value=_FakeCompletedProcess(stdout='{"findings": []}', returncode=0),
    ):
        findings = rytscan.run({"path": "./contracts"})
        assert findings == []


def test_vaultsweep_crash_with_no_output_raises_not_zero_findings():
    with (
        patch(
            "subprocess.run",
            return_value=_FakeCompletedProcess(stdout="", returncode=2, stderr="permission denied"),
        ),
        pytest.raises(AdapterError, match="scan failed"),
    ):
        vaultsweep.run({"path": "."})


def test_schemalock_mixed_report_maps_all_failed_checks():
    data = json.loads((FIXTURES / "schemalock_mixed_report.json").read_text())
    findings = schemalock.parse_report(data)
    # 7 checks in fixture, 4 failed (auth_required, status, error_envelope,
    # unknown) -> only 4 findings; passed checks are skipped.
    assert len(findings) == 4

    severity_by_rule = {f.rule_id: f.severity for f in findings}
    assert severity_by_rule == {
        "CONTRACT-AUTH_REQUIRED": "critical",
        "CONTRACT-STATUS": "high",
        "CONTRACT-ERROR_ENVELOPE": "medium",
        "CONTRACT-RATE_LIMIT": "medium",
    }

    # every failed check becomes a Finding
    assert all(f.tool == "schemalock" for f in findings)
    # passed checks never appear as findings
    assert not any(f for f in findings if f.raw.get("check_type") and f.raw["passed"])


def test_schemalock_mixed_report_only_failed_checks():
    data = json.loads((FIXTURES / "schemalock_mixed_report.json").read_text())
    findings = schemalock.parse_report(data)
    failed_types = [
        c["check_type"].lower()
        for c in data["checks"]
        if not c.get("passed", True)
    ]
    assert {f.rule_id for f in findings} == {
        f"CONTRACT-{t.upper()}" for t in failed_types
    }
    assert all(not f.raw.get("passed", False) for f in findings)


def test_schemalock_severity_lookup_is_case_insensitive():
    """Regression test: an unexpected casing like 'Auth_Required' must still map to
    critical — never silently fall through to the medium default."""
    data = {
        "checks": [
            {
                "name": "auth_bypass_case",
                "check_type": "Auth_Required",  # deliberately mismatched case
                "passed": False,
                "endpoint": "GET /escrows/{id}",
                "detail": "unauthenticated request returned 200",
            }
        ]
    }
    findings = schemalock.parse_report(data)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def _json_report_path(cmd):
    return Path(cmd[cmd.index("--json-report") + 1])


def test_schemalock_retries_once_then_succeeds():
    """A warm-up failure (nonzero exit, no report) must be retried once; if the
    second attempt produces a report we return its findings."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(calls) == 1:
            return _FakeCompletedProcess(returncode=1, stderr="connection refused")
        _json_report_path(cmd).write_text(
            json.dumps(
                {
                    "checks": [
                        {
                            "name": "status",
                            "check_type": "status",
                            "passed": False,
                            "endpoint": "GET /escrows/{id}",
                            "detail": "wrong status code",
                        }
                    ]
                }
            )
        )
        return _FakeCompletedProcess(returncode=0)

    opts = {"config": "schemalock.yaml", "base_url": "http://127.0.0.1:8000"}
    with patch("subprocess.run", side_effect=fake_run), patch("time.sleep") as fake_sleep:
        findings = schemalock.run(opts)

    assert len(calls) == 2
    fake_sleep.assert_called_once_with(schemalock.RETRY_DELAY_SECONDS)
    assert len(findings) == 1
    assert findings[0].rule_id == "CONTRACT-STATUS"


def test_schemalock_raises_when_both_attempts_fail():
    """If retry also fails (connection-refused both times, no report), raise
    AdapterError and surface the last run's stderr for diagnosis."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeCompletedProcess(returncode=1, stderr="connection refused")

    opts = {"config": "schemalock.yaml", "base_url": "http://127.0.0.1:8000"}
    with patch("subprocess.run", side_effect=fake_run), patch("time.sleep") as fake_sleep:
        with pytest.raises(AdapterError, match="no report produced.*connection refused"):
            schemalock.run(opts)

    assert len(calls) == 2
    fake_sleep.assert_called_once()


def test_schemalock_does_not_retry_when_binary_missing():
    """FileNotFoundError means the tool can never run — retry would be wasted."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        raise FileNotFoundError("no schemalock binary")

    opts = {"config": "schemalock.yaml", "base_url": "http://127.0.0.1:8000"}
    with patch("subprocess.run", side_effect=fake_run), patch("time.sleep") as fake_sleep:
        with pytest.raises(AdapterError, match="CLI not found"):
            schemalock.run(opts)

    assert len(calls) == 1
    fake_sleep.assert_not_called()
