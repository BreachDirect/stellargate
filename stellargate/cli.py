"""stellargate run --config stellargate.yaml [--json-report path] [--fail-on LEVEL]"""
from __future__ import annotations

import argparse
import json
import sys

from stellargate.aggregator import all_findings, run_all
from stellargate.config import VALID_SEVERITIES, Config, ConfigError
from stellargate.report import gate_passed, to_json, to_markdown


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stellargate")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run all configured tools")
    run_parser.add_argument("--config", default="stellargate.yaml")
    run_parser.add_argument("--json-report", default=None, help="Write JSON report to this path")
    run_parser.add_argument("--md-report", default=None, help="Write Markdown report to this path")
    run_parser.add_argument("--fail-on", default=None, help="Override fail_on threshold from config")
    run_parser.add_argument(
        "--group-by",
        default="severity",
        choices=["severity", "tool"],
        help="Group findings by severity or by tool (default: severity)",
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
    passed = gate_passed(findings, fail_on)

    print(to_markdown(results, fail_on, passed, args.group_by))

    if args.json_report:
        with open(args.json_report, "w") as f:
            json.dump(to_json(results, fail_on, passed), f, indent=2)

    if args.md_report:
        with open(args.md_report, "w") as f:
            f.write(to_markdown(results, fail_on, passed, args.group_by))

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
