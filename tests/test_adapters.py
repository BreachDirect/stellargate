import json
from pathlib import Path

from stellargate.adapters import rytscan, schemalock, vaultsweep

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
