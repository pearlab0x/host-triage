from __future__ import annotations

import shutil
import subprocess

import pytest

from host_triage import checks
from host_triage.checks import (
    CheckConfig,
    check_dmarc,
    classify_dmarc,
    dmarc_summary,
    parse_dmarc,
)
from host_triage.models import Status
from host_triage.target import parse_target


def test_parse_dmarc_reads_tags() -> None:
    record = (
        "v=DMARC1; p=reject; sp=quarantine; rua=mailto:a@example.com,mailto:b@example.com; "
        "ruf=mailto:f@example.com; pct=50; adkim=s; aspf=r; ri=3600"
    )
    info = parse_dmarc(record)
    assert info["p"] == "reject"
    assert info["sp"] == "quarantine"
    assert info["rua"] == ["mailto:a@example.com", "mailto:b@example.com"]
    assert info["ruf"] == ["mailto:f@example.com"]
    assert info["pct"] == 50
    assert info["ri"] == 3600
    assert info["adkim"] == "s"
    assert "v" not in info


def test_parse_dmarc_is_case_insensitive_and_tolerates_spacing() -> None:
    info = parse_dmarc("v=DMARC1 ;  P = None ;  RUA = mailto:x@example.com ")
    assert info["p"] == "none"
    assert info["rua"] == ["mailto:x@example.com"]


def test_parse_dmarc_keeps_non_numeric_pct_as_written() -> None:
    # A malformed pct should surface rather than crash the parse.
    assert parse_dmarc("v=DMARC1; p=reject; pct=abc")["pct"] == "abc"


def test_parse_dmarc_ignores_trailing_semicolon_and_bare_tokens() -> None:
    info = parse_dmarc("v=DMARC1; p=reject; junk; ")
    assert info == {"p": "reject"}


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=DMARC1; p=reject", Status.OK),
        ("v=DMARC1; p=quarantine", Status.OK),
        ("v=DMARC1; p=none", Status.WARN),  # monitor only, enforces nothing
        ("v=DMARC1; rua=mailto:a@example.com", Status.WARN),  # no policy tag at all
        ("v=DMARC1; p=reject; pct=50", Status.WARN),  # only half of mail is covered
        ("v=DMARC1; p=reject; pct=100", Status.OK),
    ],
)
def test_classify_dmarc(record: str, expected: Status) -> None:
    assert classify_dmarc(parse_dmarc(record)) is expected


def test_dmarc_summary_flags_monitor_only() -> None:
    summary = dmarc_summary(parse_dmarc("v=DMARC1; p=none; rua=mailto:a@example.com"))
    assert "p=none" in summary
    assert "monitor only" in summary
    assert "1 rua" in summary


def test_dmarc_summary_without_policy() -> None:
    assert "no policy" in dmarc_summary(parse_dmarc("v=DMARC1; rua=mailto:a@example.com"))


def test_dmarc_summary_reports_partial_pct() -> None:
    assert "pct=25" in dmarc_summary(parse_dmarc("v=DMARC1; p=reject; pct=25"))


def _fake_run(stdout: str) -> object:
    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    return run


def test_check_dmarc_skips_without_dig(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert check_dmarc(parse_target("example.com"), CheckConfig()).status is Status.SKIP


def test_check_dmarc_queries_the_underscore_subdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, list[str]] = {}

    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout='"v=DMARC1; p=reject"\n', stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(subprocess, "run", run)
    result = check_dmarc(parse_target("example.com"), CheckConfig())
    assert seen["argv"][-1] == "_dmarc.example.com"
    assert result.status is Status.OK
    assert result.details["queried"] == "_dmarc.example.com"


def test_check_dmarc_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(
        subprocess, "run", _fake_run('"v=DMARC1; p=reject; rua=mailto:d@example.com"\n')
    )
    result = check_dmarc(parse_target("example.com"), CheckConfig())
    assert result.status is Status.OK
    assert result.details["p"] == "reject"


def test_check_dmarc_warns_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(subprocess, "run", _fake_run(""))
    result = check_dmarc(parse_target("example.com"), CheckConfig())
    assert result.status is Status.WARN
    assert "no DMARC record" in result.summary


def test_check_dmarc_ignores_unrelated_txt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(subprocess, "run", _fake_run('"some-verification=token"\n'))
    assert check_dmarc(parse_target("example.com"), CheckConfig()).status is Status.WARN


def test_check_dmarc_warns_on_multiple(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(subprocess, "run", _fake_run('"v=DMARC1; p=reject"\n"v=DMARC1; p=none"\n'))
    result = check_dmarc(parse_target("example.com"), CheckConfig())
    assert result.status is Status.WARN
    assert "multiple" in result.summary


def test_check_dmarc_fails_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, 5)

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(subprocess, "run", run)
    result = check_dmarc(parse_target("example.com"), CheckConfig())
    assert result.status is Status.FAIL
    assert "timed out" in result.summary


def test_dmarc_in_registry() -> None:
    assert "dmarc" in checks.REGISTRY
    assert "dmarc" not in checks.DEFAULT_CHECKS
