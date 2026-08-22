from __future__ import annotations

import json

import pytest

from host_triage import checks, cli
from host_triage.models import CheckResult, Report, Status
from host_triage.render import render_json, render_text


def _stub(status: Status, summary: str = "stub") -> checks.Check:
    def _check(target: object, cfg: object) -> CheckResult:
        return CheckResult("dns", status, summary, duration_ms=1.0)

    return _check


def test_render_text_no_color_is_plain() -> None:
    report = Report(target="example.com", results=[CheckResult("dns", Status.OK, "ok", duration_ms=5)])
    out = render_text(report, color=False)
    assert "\033[" not in out
    assert "example.com" in out
    assert "dns" in out


def test_render_text_color_has_escapes() -> None:
    report = Report(target="x", results=[CheckResult("http", Status.FAIL, "500", duration_ms=5)])
    assert "\033[" in render_text(report, color=True)


def test_render_json_roundtrip() -> None:
    report = Report(target="x", results=[CheckResult("tls", Status.WARN, "soon", duration_ms=3.2)])
    data = json.loads(render_json(report))
    assert data["target"] == "x"
    assert data["ok"] is True
    assert data["checks"][0]["status"] == "warn"


def test_cli_exit_ok(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    code = cli.main(["example.com", "--checks", "dns", "--json"])
    assert code == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_cli_exit_failure(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.FAIL))
    code = cli.main(["example.com", "--checks", "dns"])
    assert code == cli.EXIT_FAILURES


def test_cli_warning_is_not_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.WARN))
    assert cli.main(["example.com", "--checks", "dns", "--json"]) == cli.EXIT_OK


def test_cli_unknown_check_is_usage_error() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["example.com", "--checks", "bogus"])
    assert exc.value.code == cli.EXIT_USAGE


def test_cli_port_override(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, int] = {}

    def _spy(target: object, cfg: object) -> CheckResult:
        captured["port"] = target.port  # type: ignore[attr-defined]
        return CheckResult("tcp", Status.OK, "ok", duration_ms=1.0)

    monkeypatch.setitem(checks.REGISTRY, "tcp", _spy)
    cli.main(["example.com", "--checks", "tcp", "--port", "8443", "--json"])
    assert captured["port"] == 8443
