from unittest.mock import patch

import pytest

from stellargate.aggregator import ToolRunResult, all_findings, run_all
from stellargate.config import Config, ToolConfig
from stellargate.report import gate_passed, to_json, to_markdown
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


def test_to_markdown_default_grouping_is_severity():
    results = make_results()
    md_default = to_markdown(results, "high", False)
    md_explicit = to_markdown(results, "high", False, group_by="severity")
    # explicitly requesting severity must not change the default output
    assert md_explicit == md_default
    assert "| Severity | Tool | Rule | Location | Message |" in md_default


def test_to_markdown_groups_by_tool():
    results = make_results()
    md = to_markdown(results, "high", False, group_by="tool")
    assert "### rytscan" in md
    assert "### vaultsweep" in md
    # per-tool tables have no redundant Tool column
    assert "| Severity | Tool | Rule | Location | Message |" not in md
    assert "AUTH-001" in md
    assert "STELLAR-001" in md


def test_to_markdown_tool_group_skips_errored_tools_and_marks_clean():
    results = make_results()
    # schemalock errored -> not shown as a findings section (it is in Tool errors)
    md = to_markdown(results, "high", False, group_by="tool")
    assert "### schemalock" not in md
    assert "schemalock CLI not found" in md
    # a healthy tool with no findings is marked as clean
    results.append(ToolRunResult("shieldscan", [], None))
    md2 = to_markdown(results, "high", False, group_by="tool")
    assert "### shieldscan" in md2
    assert "No findings. Clean run." in md2


def test_to_markdown_rejects_unknown_grouping():
    results = make_results()
    with pytest.raises(ValueError, match="bogus"):
        to_markdown(results, "high", False, group_by="bogus")


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
