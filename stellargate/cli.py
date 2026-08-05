"""stellargate run --config stellargate.yaml [--json-report path] [--fail-on LEVEL]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from stellargate.aggregator import ToolRunResult, all_findings, run_all
from stellargate.config import VALID_SEVERITIES, Config, ConfigError
from stellargate.report import diff_findings, finding_key, gate_passed, to_json, to_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stellargate")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run all configured tools")
    run_parser.add_argument("--config", default="stellargate.yaml")
    run_parser.add_argument("--json-report", default=None, help="Write JSON report to this path")
    run_parser.add_argument("--md-report", default=None, help="Write Markdown report to this path")
    run_parser.add_argument("--fail-on", default=None, help="Override fail_on threshold from config")
    run_parser.add_argument(
        "--diff-only",
        default=None,
        metavar="BASELINE.json",
        help=("Gate only on findings newly introduced since a baseline StellarGate "
              "JSON report. Loads the baseline, keeps only findings not present in it, "
              "and bases both the gate and the report on those new findings."),
    )

    args = parser.parse_args(argv)

    if args.command == "run":
        return _run(args)
    return 1


def _run(args: argparse.Namespace) -> int:
    try:
        config = Config.load(args.config)
    except ConfigError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    fail_on = (args.fail_on or config.fail_on).lower()
    if fail_on not in VALID_SEVERITIES:
        print(
            f"Invalid --fail-on '{fail_on}'; must be one of {VALID_SEVERITIES}",
            file=sys.stderr,
        )
        return 2

    results = run_all(config)
    findings = all_findings(results)
    diff_mode = False

    if args.diff_only:
        baseline = _load_baseline(args.diff_only)
        if baseline is None:
            return 2
        diff_mode = True
        findings = diff_findings(findings, baseline)
        keep = {finding_key(f) for f in findings}
        results = [
            ToolRunResult(
                r.tool,
                [f for f in r.findings if finding_key(f) in keep],
                r.error,
            )
            for r in results
        ]

    passed = gate_passed(findings, fail_on)

    print(to_markdown(results, fail_on, passed, diff_mode))

    if args.json_report:
        with open(args.json_report, "w") as f:
            json.dump(to_json(results, fail_on, passed, diff_mode), f, indent=2)

    if args.md_report:
        with open(args.md_report, "w") as f:
            f.write(to_markdown(results, fail_on, passed, diff_mode))

    return 0 if passed else 1


def _load_baseline(path: str) -> dict | None:
    """Load and validate a baseline StellarGate JSON report.

    Returns the parsed report on success, or None after printing a clear
    error to stderr. None signals the caller to exit non-zero — a missing
    or corrupt baseline is never silently treated as an empty baseline.
    """
    p = Path(path)
    if not p.exists():
        print(f"diff-only: baseline report not found: {path}", file=sys.stderr)
        return None
    try:
        with open(p) as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        print(f"diff-only: baseline {path} is not valid JSON: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"diff-only: cannot read baseline {path}: {e}", file=sys.stderr)
        return None

    if not isinstance(report, dict) or "findings" not in report:
        print(
            f"diff-only: {path} is not a StellarGate report "
            "(expected an object with a 'findings' list)",
            file=sys.stderr,
        )
        return None
    if not isinstance(report["findings"], list):
        print(f"diff-only: baseline {path} has a non-list 'findings' field", file=sys.stderr)
        return None
    for i, item in enumerate(report["findings"]):
        if not isinstance(item, dict) or "tool" not in item or "rule_id" not in item:
            print(
                f"diff-only: baseline {path} finding[{i}] is malformed "
                "(each finding needs 'tool' and 'rule_id')",
                file=sys.stderr,
            )
            return None
    return report


if __name__ == "__main__":
    sys.exit(main())
