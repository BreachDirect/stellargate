from unittest.mock import mock_open, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from stellargate.aggregator import ToolRunResult, all_findings, run_all
from stellargate.cli import _run
from stellargate.config import Config, ToolConfig
from stellargate.report import gate_passed, to_json, to_markdown
from stellargate.schema import SEVERITY_ORDER, Finding


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


def test_to_sarif_has_schema_version_and_runs():
    results = make_results()
    sarif = to_sarif(results, "high", False)
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "stellargate"
    assert driver["version"] == "0.1.0"


def test_to_sarif_severity_level_mapping():
    findings = [
        Finding("t", "R1", "critical", "m"),
        Finding("t", "R2", "high", "m"),
        Finding("t", "R3", "medium", "m"),
        Finding("t", "R4", "low", "m"),
    ]
    sarif = to_sarif(
        [ToolRunResult("t", findings, None)], "high", False
    )
    levels = [
        SEVERITY_TO_LEVEL[f.severity]
        for f in findings
    ]
    assert levels == ["error", "error", "warning", "note"]
    result_levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert result_levels == levels


def test_to_sarif_creates_one_result_per_finding_with_ruleid_and_location():
    results = make_results()
    sarif = to_sarif(results, "high", False)
    sarif_results = sarif["runs"][0]["results"]
    assert len(sarif_results) == 2
    assert [r["ruleId"] for r in sarif_results] == ["AUTH-001", "STELLAR-001"]
    auth = [r for r in sarif_results if r["ruleId"] == "AUTH-001"][0]
    uri = auth["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "vault.rs:42"


def test_to_sarif_empty_findings_yields_empty_results():
    sarif = to_sarif([ToolRunResult("t", [], None)], "high", True)
    assert sarif["runs"][0]["results"] == []
    assert "rules" not in sarif["runs"][0]["tool"]["driver"]


def test_cli_writes_sarif_report_file():
    from types import SimpleNamespace

    args = SimpleNamespace(
        config="stellargate.example.yaml",
        fail_on=None,
        json_report=None,
        sarif_report="build/report.sarif",
        md_report=None,
    )
    config = Config(
        target=".",
        fail_on="high",
        tools={},
    )
    with patch("stellargate.cli.Config.load", return_value=config), patch(
        "stellargate.cli.run_all", return_value=make_results()
    ) as mock_run_all, patch(
        "stellargate.cli.gate_passed", return_value=False
    ), patch("builtins.open", mock_open()) as mock_file:
        _run(args)
    mock_run_all.assert_called_once()
    handle = mock_file()
    written = "".join(call.args[0] for call in handle.write.call_args_list)
    import json

    data = json.loads(written)
    assert data["$schema"].endswith("sarif-2.1.0.json")
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    assert data["runs"][0]["tool"]["driver"]["name"] == "stellargate"


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


SEVERITIES = ["critical", "high", "medium", "low"]
TOOLS = ["rytscan", "schemalock", "vaultsweep", "shieldscan"]


@given(
    st.lists(
        st.builds(
            Finding,
            tool=st.sampled_from(TOOLS),
            rule_id=st.text(min_size=1),
            severity=st.sampled_from(SEVERITIES),
            message=st.text(),
        )
    )
)
@settings(max_examples=100)
def test_all_findings_sorts_strictly_by_severity_rank_desc(findings):
    """Property test: all_findings() must sort strictly by severity_rank
    descending regardless of input order, mix, or duplicates."""
    results = [ToolRunResult(f.tool, [f], None) for f in findings]
    if not findings:
        assert all_findings(results) == []
        return

    output = all_findings(results)

    assert len(output) == len(findings)
    for f in output:
        assert f.severity_rank == SEVERITY_ORDER[f.severity]
    ranks = [f.severity_rank for f in output]
    assert ranks == sorted(ranks, reverse=True)
