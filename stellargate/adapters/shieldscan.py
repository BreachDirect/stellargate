"""Adapter for ShieldScan — NOT IMPLEMENTED in Phase 1.

Upstream: https://github.com/BreachDirect/shieldscan

ShieldScan is a Docker + web-dashboard tool (OWASP ZAP integration, AI report
generation) with no clean headless JSON CLI mode today. Building this adapter
requires resolving that first — see Phase 2 issue "ShieldScan adapter" in
architecture.md for the two proposed approaches.

This stub exists so the aggregator can reference `shieldscan` in config
without a KeyError, and so config validation clearly rejects `enabled: true`
until Phase 2 lands.
"""

from __future__ import annotations

from stellargate.schema import AdapterError, Finding

TOOL_NAME = "shieldscan"


def run(options: dict) -> list[Finding]:
    raise AdapterError(
        f"{TOOL_NAME}: adapter not implemented in Phase 1. "
        f"ShieldScan has no headless JSON CLI mode yet — see architecture.md "
        f"Phase 2 for the plan. Set tools.shieldscan.enabled: false in your config."
    )
