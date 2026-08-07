"""Load and validate stellargate.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_SEVERITIES = ("critical", "high", "medium", "low")
KNOWN_TOOLS = ("rytscan", "schemalock", "vaultsweep", "shieldscan")


class ConfigError(Exception):
    pass


@dataclass
class ToolConfig:
    enabled: bool = False
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    target: str
    fail_on: str
    tools: dict[str, ToolConfig]

    @staticmethod
    def load(path: str | Path) -> Config:
        path = Path(path)
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")

        with open(path) as f:
            try:
                raw = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                raise ConfigError(f"Malformed YAML in {path}: {e}")

        target = raw.get("target", ".")
        fail_on = raw.get("fail_on", "high").lower()
        if fail_on not in VALID_SEVERITIES:
            raise ConfigError(f"Invalid fail_on '{fail_on}'; must be one of {VALID_SEVERITIES}")

        raw_tools = raw.get("tools", {})
        unknown = set(raw_tools) - set(KNOWN_TOOLS)
        if unknown:
            raise ConfigError(
                f"Unknown tool(s) in config: {sorted(unknown)}; " f"known tools are {KNOWN_TOOLS}"
            )

        tools: dict[str, ToolConfig] = {}
        for name in KNOWN_TOOLS:
            entry = raw_tools.get(name, {}) or {}
            options = {k: v for k, v in entry.items() if k != "enabled"}
            tools[name] = ToolConfig(
                enabled=bool(entry.get("enabled", False)),
                options=options,
            )

        if not any(t.enabled for t in tools.values()):
            raise ConfigError("No tools enabled in config — nothing to run.")

        return Config(target=target, fail_on=fail_on, tools=tools)
