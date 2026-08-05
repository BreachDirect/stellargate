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


class _FakeCompletedProcess:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


def test_rytscan_crash_with_no_output_raises_not_zero_findings():
    """Regression test: a tool that crashes (nonzero exit, empty stdout) must
    raise AdapterError, never be silently read as a clean 'zero findings' scan."""
    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout="", returncode=1, stderr="panic: build failed")):
        with pytest.raises(AdapterError, match="scan failed"):
            rytscan.run({"path": "./contracts"})


def test_rytscan_clean_pass_with_zero_findings_is_fine():
    """A genuine clean scan (exit 0, empty JSON findings list) is a legitimate pass —
    only a crash (nonzero exit + empty stdout) should raise."""
    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout='{"findings": []}', returncode=0)):
        findings = rytscan.run({"path": "./contracts"})
        assert findings == []


def test_vaultsweep_crash_with_no_output_raises_not_zero_findings():
    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout="", returncode=2, stderr="permission denied")):
        with pytest.raises(AdapterError, match="scan failed"):
            vaultsweep.run({"path": "."})


def test_schemalock_run_multiple_base_urls_runs_each_and_labels_findings():
    """base_urls list -> one CLI invocation per URL, findings labelled by URL."""
    data = {
        "checks": [
            {
                "name": "get_escrow",
                "check_type": "status",
                "passed": False,
                "endpoint": "GET /escrows/{id}",
                "detail": "got 500, expected 200",
            }
        ]
    }
    calls = []
    reports = [data, data]

    def _side_effect(cmd, *args, **kwargs):
        calls.append(cmd)
        idx = cmd.index("--json-report")
        Path(cmd[idx + 1]).write_text(json.dumps(reports.pop(0)))

    with patch("subprocess.run", side_effect=_side_effect):
        findings = schemalock.run(
            {"config": "./schemalock.yaml", "base_urls": ["http://staging:9000", "http://prod:9000"]}
        )

    assert len(calls) == 2
    assert calls[0][calls[0].index("--base-url") + 1] == "http://staging:9000"
    assert calls[1][calls[1].index("--base-url") + 1] == "http://prod:9000"
    assert [f.location for f in findings] == [
        "http://staging:9000: GET /escrows/{id}",
        "http://prod:9000: GET /escrows/{id}",
    ]


def test_schemalock_legacy_single_base_url_calls_once():
    """Legacy base_url (single string) still invokes the CLI once, URL-tagged."""
    data = {
        "checks": [
            {
                "name": "get_escrow",
                "check_type": "status",
                "passed": False,
                "endpoint": "GET /escrows/{id}",
                "detail": "got 500, expected 200",
            }
        ]
    }
    calls = []

    def _side_effect(cmd, *args, **kwargs):
        calls.append(cmd)
        idx = cmd.index("--json-report")
        Path(cmd[idx + 1]).write_text(json.dumps(data))

    with patch("subprocess.run", side_effect=_side_effect):
        findings = schemalock.run(
            {"config": "./schemalock.yaml", "base_url": "http://127.0.0.1:8000"}
        )

    assert len(calls) == 1
    assert calls[0][calls[0].index("--base-url") + 1] == "http://127.0.0.1:8000"
    assert len(findings) == 1


def test_schemalock_base_urls_dict_uses_env_keys_as_labels():
    data = {
        "checks": [
            {
                "name": "get_escrow",
                "check_type": "status",
                "passed": False,
                "endpoint": "GET /escrows/{id}",
                "detail": "got 500, expected 200",
            }
        ]
    }
    reported = [data, data]

    def _side_effect(cmd, *args, **kwargs):
        idx = cmd.index("--json-report")
        Path(cmd[idx + 1]).write_text(json.dumps(reported.pop(0)))

    with patch("subprocess.run", side_effect=_side_effect):
        findings = schemalock.run(
            {
                "config": "./schemalock.yaml",
                "base_urls": {"staging": "http://staging:9000", "prod": "http://prod:9000"},
            }
        )

    assert [f.location for f in findings] == [
        "staging: GET /escrows/{id}",
        "prod: GET /escrows/{id}",
    ]


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
