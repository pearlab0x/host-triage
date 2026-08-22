"""Data models shared across checks and renderers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Outcome of a single check.

    Ordered by severity so the worst status in a run can be found with ``max``.
    """

    OK = "ok"
    SKIP = "skip"
    WARN = "warn"
    FAIL = "fail"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @property
    def is_failure(self) -> bool:
        return self is Status.FAIL


_SEVERITY: dict[Status, int] = {
    Status.OK: 0,
    Status.SKIP: 1,
    Status.WARN: 2,
    Status.FAIL: 3,
}


@dataclass(slots=True)
class CheckResult:
    """The result of running one check against a target."""

    name: str
    status: Status
    summary: str
    details: dict[str, object] = field(default_factory=dict)
    duration_ms: float | None = None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {
            "name": self.name,
            "status": self.status.value,
            "summary": self.summary,
            "details": self.details,
        }
        if self.duration_ms is not None:
            out["duration_ms"] = round(self.duration_ms, 2)
        return out


@dataclass(slots=True)
class Report:
    """Aggregated results for a single target."""

    target: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def worst(self) -> Status:
        if not self.results:
            return Status.SKIP
        return max((r.status for r in self.results), key=lambda s: s.severity)

    @property
    def ok(self) -> bool:
        """True when no check failed. Warnings do not count as failure."""
        return not any(r.status.is_failure for r in self.results)

    @property
    def failures(self) -> int:
        return sum(1 for r in self.results if r.status.is_failure)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "ok": self.ok,
            "worst": self.worst.value,
            "checks": [r.to_dict() for r in self.results],
        }
