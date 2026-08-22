from __future__ import annotations

from host_triage.models import CheckResult, Report, Status


def test_status_severity_order() -> None:
    assert Status.OK.severity < Status.SKIP.severity < Status.WARN.severity < Status.FAIL.severity


def test_check_result_to_dict_includes_duration() -> None:
    r = CheckResult("dns", Status.OK, "ok", details={"a": 1}, duration_ms=12.345)
    d = r.to_dict()
    assert d == {"name": "dns", "status": "ok", "summary": "ok", "details": {"a": 1}, "duration_ms": 12.35}


def test_check_result_to_dict_omits_duration_when_none() -> None:
    assert "duration_ms" not in CheckResult("dns", Status.SKIP, "n/a").to_dict()


def test_report_worst_and_ok() -> None:
    report = Report(
        target="example.com",
        results=[
            CheckResult("dns", Status.OK, ""),
            CheckResult("tls", Status.WARN, ""),
        ],
    )
    assert report.worst is Status.WARN
    assert report.ok is True  # warnings do not fail the run
    assert report.failures == 0


def test_report_failure_counts() -> None:
    report = Report(
        target="x",
        results=[CheckResult("http", Status.FAIL, ""), CheckResult("tcp", Status.FAIL, "")],
    )
    assert report.ok is False
    assert report.failures == 2
    assert report.worst is Status.FAIL


def test_empty_report_is_skip() -> None:
    report = Report(target="x")
    assert report.worst is Status.SKIP
    assert report.ok is True
