"""Unified finding schema every adapter normalizes into."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str
    message: str
    location: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        sev = self.severity.lower()
        if sev not in SEVERITY_ORDER:
            raise ValueError(
                f"Invalid severity '{self.severity}' for {self.tool}/{self.rule_id}; "
                f"must be one of {list(SEVERITY_ORDER)}"
            )
        self.severity = sev

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AdapterError(Exception):
    """Raised when an adapter itself fails (tool missing, bad output) —
    never raised just because the underlying tool found issues."""
