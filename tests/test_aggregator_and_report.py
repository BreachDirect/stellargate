import json
from unittest.mock import patch

from stellargate.aggregator import ToolRunResult, all_findings, run_all
from stellargate.config import Config, ToolConfig
from stellargate.report import (
    diff_findings,
    finding_key,
    gate_passed,
    to_json,
    to_markdown,
)
from stellargate.schema import Finding


def make_results():
    return [
        ToolRunResult(
            "rytscan",
            [Finding("rytscan", "AUTH-001", "high", "no auth check", "vault.rs:42")],
            None,
        ),
        ToolRunResult(
            "vaultsweep",
            [Finding("vaultsweep", "STELLAR-001", "critical", "leaked secret key", ".env:3")],
            None,
        ),
        ToolRunResult("schemalock", [], "schemalock CLI not found"),
    ]


def test_all_findings_sorted_by_severity_desc():
    results = make_results()
    findings = all_findings(results)
    assert [f.severity for f in findings] == ["critical", "high"]


def test_gate_passed_fails_on_critical_when_threshold_high():
    results = make_results()
    findings = all_findings(results)
    assert gate_passed(findings, "high") is False  # critical >= high threshold


def test_gate_passed_true_when_no_findings():
    assert gate_passed([], "high") is True


def test_to_json_shape():
    results = make_results()
    report = to_json(results, "high", gate_passed(all_findings(results), "high"))
    assert report["passed"] is False
    assert report["summary"]["critical"] == 1
    assert report["summary"]["high"] == 1
    assert len(report["findings"]) == 2
    tool_names = {t["tool"] for t in report["tools"]}
    assert tool_names == {"rytscan", "vaultsweep", "schemalock"}
    errored = [t for t in report["tools"] if t["tool"] == "schemalock"][0]
    assert errored["error"] == "schemalock CLI not found"


def test_to_markdown_shows_failed_status_and_tool_error():
    results = make_results()
    md = to_markdown(results, "high", False)
    assert "FAILED" in md
    assert "schemalock CLI not found" in md
    assert "AUTH-001" in md
    assert "STELLAR-001" in md


def test_run_all_survives_an_unexpected_adapter_exception():
    """Regression test: a bug in one adapter (e.g. a bare KeyError, not an
    AdapterError) must not crash the whole run — every other tool's findings
    still belong in the report."""
    config = Config(
        target=".",
        fail_on="high",
        tools={
            "rytscan": ToolConfig(enabled=True, options={"path": "."}),
            "vaultsweep": ToolConfig(enabled=False, options={}),
            "schemalock": ToolConfig(enabled=False, options={}),
            "shieldscan": ToolConfig(enabled=False, options={}),
        },
    )
    with patch("stellargate.adapters.rytscan.run", side_effect=KeyError("boom")):
        results = run_all(config)

    assert len(results) == 1
    assert results[0].tool == "rytscan"
    assert results[0].error is not None
    assert "unexpected adapter error" in results[0].error
    # crucially: run_all itself did not raise


def test_finding_key_matches_live_objects_and_json_dicts():
    f = Finding("rytscan", "AUTH-001", "high", "no auth check", "vault.rs:42")
    assert finding_key(f) == ("rytscan", "AUTH-001", "vault.rs:42")
    assert finding_key(f.to_dict()) == finding_key(f)


def test_finding_key_is_location_sensitive():
    a = Finding("rytscan", "AUTH-001", "high", "x", "vault.rs:42")
    b = Finding("rytscan", "AUTH-001", "high", "x", "vault.rs:99")
    assert finding_key(a) != finding_key(b)


def test_diff_findings_drops_baseline_findings_keeps_new():
    current = [
        Finding("rytscan", "AUTH-001", "high", "no auth check", "vault.rs:42"),
        Finding("rytscan", "AUTH-002", "high", "new rule hit", "vault.rs:99"),
    ]
    baseline = {
        "findings": [
            {"tool": "rytscan", "rule_id": "AUTH-001", "location": "vault.rs:42"},
        ]
    }
    new = diff_findings(current, baseline)
    assert [f.rule_id for f in new] == ["AUTH-002"]


def test_diff_findings_ignores_severity_message_changes_on_same_key():
    """Same (tool, rule_id, location) with a reworded message is not 'new'."""
    current = [Finding("rytscan", "AUTH-001", "high", "rewritten message", "vault.rs:42")]
    baseline = {
        "findings": [
            {"tool": "rytscan", "rule_id": "AUTH-001", "location": "vault.rs:42",
             "severity": "high", "message": "old wording"},
        ]
    }
    assert diff_findings(current, baseline) == []


def test_diff_gate_ignores_pre_existing_findings():
    """The whole point of --diff-only: gating on regressions, not history."""
    results = make_results()  # AUTH-001 (high) + STELLAR-001 (critical)
    baseline = {
        "findings": [
            {"tool": "rytscan", "rule_id": "AUTH-001", "location": "vault.rs:42"},
            {"tool": "vaultsweep", "rule_id": "STELLAR-001", "location": ".env:3"},
        ]
    }
    findings = diff_findings(all_findings(results), baseline)
    assert findings == []
    assert gate_passed(findings, "high") is True


def test_diff_gate_fails_on_newly_introduced_critical():
    current = [
        Finding("rytscan", "AUTH-001", "high", "no auth check", "vault.rs:42"),
        Finding("vaultsweep", "STELLAR-999", "critical", "new leak", ".env:9"),
    ]
    baseline = {
        "findings": [
            {"tool": "rytscan", "rule_id": "AUTH-001", "location": "vault.rs:42"},
        ]
    }
    new = diff_findings(current, baseline)
    assert [f.rule_id for f in new] == ["STELLAR-999"]
    assert gate_passed(new, "high") is False


def test_to_json_marks_diff_mode():
    results = make_results()
    normal = to_json(results, "high", False)
    diff = to_json(results, "high", False, diff_mode=True)
    assert normal["diff"] is False
    assert diff["diff"] is True


def test_to_markdown_annotates_diff_mode_in_title():
    results = make_results()
    md = to_markdown(results, "high", False, diff_mode=True)
    assert "diff mode" in md
    assert "AUTH-001" in md
    assert "STELLAR-001" in md


def _dummy_config():
    return Config(target=".", fail_on="high", tools={})


def _run_cli(argv, capsys):
    from stellargate import cli

    with patch("stellargate.cli.Config.load", return_value=_dummy_config()), patch(
        "stellargate.cli.run_all", return_value=make_results()
    ):
        rc = cli.main(argv)
    return rc, capsys.readouterr()


def test_cli_diff_only_passes_when_only_baseline_findings(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "findings": [
                    {"tool": "rytscan", "rule_id": "AUTH-001", "location": "vault.rs:42"},
                    {"tool": "vaultsweep", "rule_id": "STELLAR-001", "location": ".env:3"},
                ]
            }
        )
    )
    rc, captured = _run_cli(
        ["run", "--config", "x.yaml", "--diff-only", str(baseline)], capsys
    )
    assert rc == 0  # no new findings -> pass
    assert "diff mode" in captured.out
    assert "AUTH-001" not in captured.out
    assert "STELLAR-001" not in captured.out


def test_cli_diff_only_fails_on_new_finding(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"findings": [{"tool": "rytscan", "rule_id": "AUTH-001", "location": "vault.rs:42"}]})
    )
    rc, captured = _run_cli(
        ["run", "--config", "x.yaml", "--diff-only", str(baseline)], capsys
    )
    assert rc == 1  # STELLAR-001 is newly introduced -> gate fails
    assert "STELLAR-001" in captured.out
    assert "diff mode" in captured.out


def test_cli_diff_only_rejects_missing_baseline(tmp_path, capsys):
    missing = tmp_path / "nope.json"
    rc, captured = _run_cli(["run", "--config", "x.yaml", "--diff-only", str(missing)], capsys)
    assert rc == 2
    assert "baseline report not found" in captured.err


def test_cli_diff_only_rejects_corrupt_baseline(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{not json")
    rc, captured = _run_cli(["run", "--config", "x.yaml", "--diff-only", str(baseline)], capsys)
    assert rc == 2
    assert "not valid JSON" in captured.err


def test_cli_diff_only_rejects_non_report_baseline(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"unrelated": True}))
    rc, captured = _run_cli(["run", "--config", "x.yaml", "--diff-only", str(baseline)], capsys)
    assert rc == 2
    assert "not a StellarGate report" in captured.err
