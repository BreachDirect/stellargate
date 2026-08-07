import threading
import time
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from stellargate.aggregator import ToolRunResult, all_findings, run_all
from stellargate.config import Config, ToolConfig
from stellargate.report import gate_passed, to_json, to_markdown
from stellargate.schema import AdapterError, Finding


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


def test_run_all_runs_enabled_adapters_concurrently_with_barrier():
    """If adapters run in parallel, all three reach the barrier and release;
    run sequentially the first would time out and its result would be an error."""
    barrier = threading.Barrier(3)  # one party per enabled adapter

    def wait(_options):
        barrier.wait(timeout=5)
        return []

    config = Config(
        target=".",
        fail_on="high",
        tools={
            "rytscan": ToolConfig(enabled=True, options={}),
            "schemalock": ToolConfig(enabled=True, options={}),
            "vaultsweep": ToolConfig(enabled=True, options={}),
            "shieldscan": ToolConfig(enabled=False, options={}),
        },
    )
    with (
        patch("stellargate.adapters.rytscan.run", side_effect=wait),
        patch("stellargate.adapters.schemalock.run", side_effect=wait),
        patch("stellargate.adapters.vaultsweep.run", side_effect=wait),
    ):
        results = run_all(config)

    assert len(results) == 3
    # If adapters had run sequentially, the first would have timed out at the
    # barrier and surfaced as an unexpected error — no errors proves overlap.
    assert all(r.error is None for r in results)


def test_run_all_wall_time_less_than_sequential_sum():
    def slow(_options):
        time.sleep(0.2)
        return []

    config = Config(
        target=".",
        fail_on="high",
        tools={
            "rytscan": ToolConfig(enabled=True, options={}),
            "schemalock": ToolConfig(enabled=True, options={}),
            "vaultsweep": ToolConfig(enabled=True, options={}),
            "shieldscan": ToolConfig(enabled=True, options={}),
        },
    )
    start = time.perf_counter()
    with (
        patch("stellargate.adapters.rytscan.run", side_effect=slow),
        patch("stellargate.adapters.schemalock.run", side_effect=slow),
        patch("stellargate.adapters.vaultsweep.run", side_effect=slow),
        patch("stellargate.adapters.shieldscan.run", side_effect=slow),
    ):
        run_all(config)
    elapsed = time.perf_counter() - start
    # Sequential total is 0.8s; concurrent should be ~0.2s + scheduling
    # overhead. A generous ceiling still proves parallelism.
    assert elapsed < 0.7


def test_run_all_preserves_config_order_under_concurrency():
    config = Config(
        target=".",
        fail_on="high",
        tools={
            "rytscan": ToolConfig(enabled=True, options={}),
            "schemalock": ToolConfig(enabled=True, options={}),
            "vaultsweep": ToolConfig(enabled=True, options={}),
            "shieldscan": ToolConfig(enabled=True, options={}),
        },
    )

    def slow(_options):
        time.sleep(0.05)
        return []

    with (
        patch("stellargate.adapters.rytscan.run", side_effect=slow),
        patch("stellargate.adapters.schemalock.run", side_effect=slow),
        patch("stellargate.adapters.vaultsweep.run", side_effect=slow),
        patch("stellargate.adapters.shieldscan.run", side_effect=slow),
    ):
        results = run_all(config)

    assert [r.tool for r in results] == ["rytscan", "schemalock", "vaultsweep", "shieldscan"]


def test_run_all_error_in_one_concurrent_adapter_does_not_break_others():
    config = Config(
        target=".",
        fail_on="high",
        tools={
            "rytscan": ToolConfig(enabled=True, options={}),
            "schemalock": ToolConfig(enabled=True, options={}),
            "vaultsweep": ToolConfig(enabled=True, options={}),
            "shieldscan": ToolConfig(enabled=True, options={}),
        },
    )
    with (
        patch(
            "stellargate.adapters.rytscan.run",
            side_effect=AdapterError("rytscan tool missing"),
        ),
        patch("stellargate.adapters.schemalock.run", return_value=[]),
        patch("stellargate.adapters.vaultsweep.run", side_effect=KeyError("boom")),
        patch("stellargate.adapters.shieldscan.run", return_value=[]),
    ):
        results = run_all(config)

    assert [r.tool for r in results] == ["rytscan", "schemalock", "vaultsweep", "shieldscan"]
    assert results[0].error == "rytscan tool missing"
    assert results[1].error is None
    assert results[2].error is not None
    assert "unexpected adapter error" in results[2].error
    assert results[3].error is None
