from __future__ import annotations

import sys
import time

import pytest

from host_triage import checks, cli
from host_triage.models import CheckResult, Status
from host_triage.render import CLEAR_SCREEN


def _stub(status: Status) -> checks.Check:
    def _check(target: object, cfg: object) -> CheckResult:
        return CheckResult("dns", status, "stub", duration_ms=1.0)

    return _check


def _stop_after(n: int, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Let the watch loop run ``n`` cycles, then interrupt it as ctrl-c would."""
    counter = {"cycles": 0}

    def fake_sleep(_seconds: float) -> None:
        counter["cycles"] += 1
        if counter["cycles"] >= n:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)
    return counter


def test_watch_repeats_until_interrupted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    counter = _stop_after(3, monkeypatch)
    code = cli.main(["example.com", "-c", "dns", "--watch", "0.01"])
    assert code == cli.EXIT_OK
    assert counter["cycles"] == 3
    assert capsys.readouterr().out.count("host-triage  example.com") == 3


def test_watch_returns_the_last_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.FAIL))
    _stop_after(2, monkeypatch)
    assert cli.main(["example.com", "-c", "dns", "--watch", "0.01"]) == cli.EXIT_FAILURES


def test_watch_honours_the_fail_on_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.WARN))
    _stop_after(1, monkeypatch)
    code = cli.main(["example.com", "-c", "dns", "--watch", "0.01", "--fail-on", "warn"])
    assert code == cli.EXIT_FAILURES


def test_watch_uses_the_default_interval_when_bare(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[float] = []

    def fake_sleep(seconds: float) -> None:
        seen.append(seconds)
        raise KeyboardInterrupt

    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    monkeypatch.setattr(time, "sleep", fake_sleep)
    cli.main(["example.com", "-c", "dns", "--watch"])
    assert seen == [cli.DEFAULT_WATCH_INTERVAL]


def test_watch_does_not_clear_when_not_a_tty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Piping to a file or another process must stay free of cursor escapes.
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    _stop_after(2, monkeypatch)
    cli.main(["example.com", "-c", "dns", "--watch", "0.01"])
    out = capsys.readouterr().out
    assert CLEAR_SCREEN not in out
    assert "ctrl-c to stop" not in out


def test_watch_clears_and_annotates_on_a_tty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    _stop_after(2, monkeypatch)
    cli.main(["example.com", "-c", "dns", "--watch", "0.01"])
    out = capsys.readouterr().out
    assert out.count(CLEAR_SCREEN) == 2
    assert "ctrl-c to stop" in out


def test_watch_with_json_emits_one_document_per_cycle(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setitem(checks.REGISTRY, "dns", _stub(Status.OK))
    _stop_after(2, monkeypatch)
    cli.main(["example.com", "-c", "dns", "--watch", "0.01", "--json"])
    out = capsys.readouterr().out
    assert CLEAR_SCREEN not in out  # never corrupt a machine-readable stream
    assert out.count('"target"') == 2


@pytest.mark.parametrize("interval", ["0", "-1"])
def test_non_positive_watch_interval_is_usage_error(interval: str) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["example.com", "-c", "dns", "--watch", interval])
    assert exc.value.code == cli.EXIT_USAGE
