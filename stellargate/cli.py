"""stellargate run --config stellargate.yaml [--json-report path] [--fail-on LEVEL]"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from stellargate.aggregator import all_findings, run_all
from stellargate.config import VALID_SEVERITIES, Config, ConfigError
from stellargate.report import gate_passed, to_json, to_markdown

logger = logging.getLogger("stellargate")

DEFAULT_LEVEL = logging.WARNING


def _configure_logging(level: int) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.setLevel(level)
    logger.addHandler(handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="stellargate")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Emit INFO diagnostics to stderr",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only emit WARNING/ERROR diagnostics to stderr",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Run all configured tools",
        epilog=(
            "exit codes:\n"
            "  0  pass - every enabled tool's findings stay below the configured "
            "'fail_on' threshold\n"
            "  1  fail - one or more findings reach or exceed the 'fail_on' "
            "threshold, the gate does not pass\n"
            "  2  error - configuration or argument error (config missing or "
            "unparsable, invalid --fail-on value, etc.)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_parser.add_argument("--config", default="stellargate.yaml")
    run_parser.add_argument("--json-report", default=None, help="Write JSON report to this path")
    run_parser.add_argument("--md-report", default=None, help="Write Markdown report to this path")
    run_parser.add_argument(
        "--fail-on", default=None, help="Override fail_on threshold from config"
    )

    args = parser.parse_args(argv)

    _configure_logging(_resolve_level(args))

    if args.command == "run":
        return _run(args)
    return 1


def _resolve_level(args: argparse.Namespace) -> int:
    if args.verbose:
        return logging.DEBUG
    if args.quiet:
        return logging.ERROR
    return DEFAULT_LEVEL


def _run(args: argparse.Namespace) -> int:
    try:
        config = Config.load(args.config)
    except ConfigError as e:
        logger.error("Config error: %s", e)
        return 2

    fail_on = (args.fail_on or config.fail_on).lower()
    if fail_on not in VALID_SEVERITIES:
        logger.error(
            "Invalid --fail-on '%s'; must be one of %s", fail_on, VALID_SEVERITIES
        )
        return 2

    enabled = [name for name, tc in config.tools.items() if tc.enabled]
    logger.info("Running %d tool(s): %s", len(enabled), ", ".join(enabled))

    results = run_all(config)
    findings = all_findings(results)
    passed = gate_passed(findings, fail_on)

    for r in results:
        if r.error:
            logger.warning("Tool %s errored: %s", r.tool, r.error)
        else:
            logger.info("Tool %s produced %d finding(s)", r.tool, len(r.findings))

    logger.info("Gate result: %s (fail_on=%s)", "passed" if passed else "failed", fail_on)

    # The Markdown report is the tool's primary output: it must go to stdout
    # verbatim so CI/scripts can capture it. Diagnostics use logging (stderr).
    print(to_markdown(results, fail_on, passed))

    if args.json_report:
        with open(args.json_report, "w") as f:
            json.dump(to_json(results, fail_on, passed), f, indent=2)

    if args.md_report:
        with open(args.md_report, "w") as f:
            f.write(to_markdown(results, fail_on, passed))

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
