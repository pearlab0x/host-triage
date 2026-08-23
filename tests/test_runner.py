from __future__ import annotations

import time

import pytest

from host_triage import checks
from host_triage.checks import CheckConfig
from host_triage.models import CheckResult, Status
from host_triage.runner import auto_jobs, run_many, run_target


def _ok_check(target: object, cfg: object) -> CheckResult:
    return CheckResult("dns", Status.OK, "ok", duration_ms=1.0)


@pytest.mark.parametrize(
    ("count", "requested", "expected"),
    [(1, 0, 1), (5, 0, 5), (50, 0, 10), (0, 0, 1), (5, 3, 3), (2, 8, 8)],
)
def test_auto_jobs(count: int, requested: int, expected: int) -> None:
    assert auto_jobs(count, requested) == expected


def test_run_target_invalid_is_isolated() -> None:
    report = run_target("example.com:0", ["dns"], CheckConfig())
    assert report.ok is False
    assert report.results[0].name == "target"
    assert report.results[0].status is Status.FAIL


def test_run_target_applies_port_override(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, int] = {}

    def spy(target: object, cfg: object) -> CheckResult:
        seen["port"] = target.port  # type: ignore[attr-defined]
        return CheckResult("tcp", Status.OK, "ok", duration_ms=1.0)

    monkeypatch.setitem(checks.REGISTRY, "tcp", spy)
    run_target("example.com", ["tcp"], CheckConfig(), port=9000)
    assert seen["port"] == 9000


def test_run_many_preserves_input_order(monkeypatch: pytest.MonkeyPatch) -> None:
    # Later targets finish sooner; output order must still match input order.
    def slow_by_name(target: object, cfg: object) -> CheckResult:
        host = target.host  # type: ignore[attr-defined]
        delay = {"a.com": 0.03, "b.com": 0.01, "c.com": 0.0}.get(host, 0.0)
        time.sleep(delay)
        return CheckResult("dns", Status.OK, host, duration_ms=1.0)

    monkeypatch.setitem(checks.REGISTRY, "dns", slow_by_name)
    reports = run_many(["a.com", "b.com", "c.com"], ["dns"], CheckConfig(), jobs=4)
    assert [r.target for r in reports] == ["a.com", "b.com", "c.com"]


def test_run_many_sequential_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _ok_check)
    reports = run_many(["a.com", "b.com"], ["dns"], CheckConfig(), jobs=1)
    assert len(reports) == 2
    assert all(r.ok for r in reports)


def test_run_many_single_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _ok_check)
    reports = run_many(["only.com"], ["dns"], CheckConfig(), jobs=8)
    assert len(reports) == 1
