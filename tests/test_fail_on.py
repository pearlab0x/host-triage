from __future__ import annotations

import json

import pytest

from host_triage import checks, cli
from host_triage.models import CheckResult, Report, Status
from host_triage.render import render_text


def _stub(status: Status, summary: str = "stub") -> checks.Check:
    def _check(target: object, cfg: object) -> CheckResult:
        return CheckResult("dns", status, summary, duration_ms=1.0)

    return _check


def _report(*statuses: Status) -> Report:
    return Report(
        target="example.com",
        results=[CheckResult(f"c{i}", s, "x") for i, s in enumerate(statuses)],
    )


# --------------------------------------------------------------------------- #
# Report.breaches / passes
# --------------------------------------------------------------------------- #
def test_breaches_counts_by_severity() -> None:
    report = _report(Status.OK, Status.WARN, Status.FAIL, Status.SKIP)
    assert report.breaches(Status.FAIL) == 1
    assert report.breaches(Status.WARN) == 2


def test_skip_never_counts_as_a_breach() -> None:
    # SKIP sorts between OK and WARN, so --fail-on warn must not trip on it.
    report = _report(Status.OK, Status.SKIP)
    assert report.breaches(Status.WARN) == 0
    assert report.passes(Status.WARN) is True


def test_passes_defaults_to_the_historical_rule() -> None:
    warned = _report(Status.WARN)
    assert warned.passes() is True
    assert warned.ok is True
    assert warned.passes(Status.WARN) is False


def test_empty_report_passes_every_threshold() -> None:
    empty = Report(target="x")
    assert empty.passes(Status.FAIL) is True
    assert empty.passes(Status.WARN) is True


def test_to_dict_ok_reflects_the_threshold() -> None:
    report = _report(Status.WARN)
    assert report.to_dict()["ok"] is True
    assert report.to_dict(Status.WARN)["ok"] is False


# --------------------------------------------------------------------------- #
# CLI gating
# --------------------------------------------------------------------------- #
def test_fail_on_warn_exits_nonzero_on_a_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.WARN))
    assert cli.main(["example.com", "-c", "dns", "--fail-on", "warn", "--json"]) == (
        cli.EXIT_FAILURES
    )


def test_fail_on_warn_still_passes_when_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    assert cli.main(["example.com", "-c", "dns", "--fail-on", "warn", "--json"]) == cli.EXIT_OK


def test_default_gate_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.WARN))
    assert cli.main(["example.com", "-c", "dns", "--json"]) == cli.EXIT_OK


def test_fail_on_warn_marks_json_not_ok(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.WARN))
    cli.main(["example.com", "-c", "dns", "--fail-on", "warn", "--json"])
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_fail_on_warn_counts_batch_failures(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def mixed(target: object, cfg: object) -> CheckResult:
        status = Status.WARN if getattr(target, "host", "") == "warn.com" else Status.OK
        return CheckResult("dns", status, "x", duration_ms=1.0)

    monkeypatch.setitem(checks.REGISTRY, "dns", mixed)
    code = cli.main(["ok.com", "warn.com", "-c", "dns", "--fail-on", "warn", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_FAILURES
    assert data["failures"] == 1
    assert data["ok"] is False


def test_invalid_fail_on_value_is_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["example.com", "--fail-on", "everything"])
    assert exc.value.code == cli.EXIT_USAGE


# --------------------------------------------------------------------------- #
# the rendered count must match the exit code
# --------------------------------------------------------------------------- #
def test_header_counts_failures_under_the_default_threshold() -> None:
    out = render_text(_report(Status.FAIL, Status.WARN), color=False)
    assert "(1 check(s) failed)" in out


def test_header_counts_warnings_under_fail_on_warn() -> None:
    out = render_text(_report(Status.FAIL, Status.WARN), color=False, threshold=Status.WARN)
    assert "(2 check(s) at or above warn)" in out


def test_header_is_bare_when_nothing_breaches() -> None:
    out = render_text(_report(Status.OK), color=False, threshold=Status.WARN)
    assert "check(s)" not in out
