from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from host_triage import checks, cli
from host_triage.models import CheckResult, Report, Status
from host_triage.render import render_json, render_text


def _stub(status: Status, summary: str = "stub") -> checks.Check:
    def _check(target: object, cfg: object) -> CheckResult:
        return CheckResult("dns", status, summary, duration_ms=1.0)

    return _check


def test_render_text_no_color_is_plain() -> None:
    report = Report(
        target="example.com", results=[CheckResult("dns", Status.OK, "ok", duration_ms=5)]
    )
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


def test_cli_exit_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
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


def test_cli_multi_target_json_shape(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    code = cli.main(["a.com", "b.com", "--checks", "dns", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_OK
    assert data["ok"] is True
    assert data["failures"] == 0
    assert [t["target"] for t in data["targets"]] == ["a.com", "b.com"]


def test_cli_multi_target_worst_case_exit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = {"n": 0}

    def flaky(target: object, cfg: object) -> CheckResult:
        calls["n"] += 1
        status = Status.FAIL if getattr(target, "host", "") == "bad.com" else Status.OK
        return CheckResult("dns", status, "x", duration_ms=1.0)

    monkeypatch.setitem(checks.REGISTRY, "dns", flaky)
    code = cli.main(["good.com", "bad.com", "--checks", "dns", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_FAILURES
    assert data["failures"] == 1


def test_cli_reads_targets_from_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    target_file = tmp_path / "hosts.txt"
    target_file.write_text("a.com\n# comment\nb.com\n", encoding="utf-8")
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    cli.main(["-f", str(target_file), "--checks", "dns", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert [t["target"] for t in data["targets"]] == ["a.com", "b.com"]


def test_cli_no_targets_is_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Pretend stdin is a terminal so no targets are read implicitly.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--checks", "dns"])
    assert exc.value.code == cli.EXIT_USAGE
