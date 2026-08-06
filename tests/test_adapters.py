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


_RTS_SCAN_FINDINGS = json.dumps(
    {
        "findings": [
            {
                "rule_id": "AUTH-001",
                "severity": "high",
                "message": "auth bypass",
                "location": "contract.rs:42",
            }
        ]
    }
)


def _make_contract_dir(tmp_path, content="pub fn main() {}"):
    d = tmp_path / "contracts"
    d.mkdir()
    (d / "contract.rs").write_text(content)
    return d


def _run_in(tmp_path):
    d = _make_contract_dir(tmp_path)
    cache = tmp_path / "cache.json"
    return d, rytscan.run({"path": str(d), "cache_file": str(cache)})


def test_rytscan_second_run_reuses_cache_without_cli(tmp_path):
    """A file unchanged since the last run must not re-invoke the CLI, and the
    cached findings must still be returned."""
    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout=_RTS_SCAN_FINDINGS)) as m:
        d = _make_contract_dir(tmp_path)
        cache = tmp_path / "cache.json"
        opts = {"path": str(d), "cache_file": str(cache)}

        first = rytscan.run(opts)
        second = rytscan.run(opts)

        assert [f.rule_id for f in first] == ["AUTH-001"]
        assert [f.rule_id for f in second] == ["AUTH-001"]
        assert m.call_count == 1  # only the first run hit the CLI


def test_rytscan_changed_content_rescans(tmp_path):
    """If a scanned file's content changes, the CLI must be called again."""
    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout=_RTS_SCAN_FINDINGS)) as m:
        d = _make_contract_dir(tmp_path, content="initial")
        cache = tmp_path / "cache.json"
        opts = {"path": str(d), "cache_file": str(cache)}

        first = rytscan.run(opts)
        assert m.call_count == 1

        (d / "contract.rs").write_text("changed body foo bar")

        second = rytscan.run(opts)
        assert m.call_count == 2  # content hash changed -> rescan
        assert [f.rule_id for f in second] == ["AUTH-001"]


def test_rytscan_corrupted_cache_rescans(tmp_path):
    """A corrupt cache file must be ignored and trigger a fresh scan, not crash."""
    d = _make_contract_dir(tmp_path)
    cache = tmp_path / "cache.json"
    cache.write_text("{ this is not valid json")
    opts = {"path": str(d), "cache_file": str(cache)}

    with patch("subprocess.run", return_value=_FakeCompletedProcess(stdout=_RTS_SCAN_FINDINGS)) as m:
        findings = rytscan.run(opts)

    assert m.call_count == 1
    assert [f.rule_id for f in findings] == ["AUTH-001"]


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
