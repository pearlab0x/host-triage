from __future__ import annotations

import shutil
import subprocess

import pytest

from host_triage import checks
from host_triage.checks import (
    CheckConfig,
    check_spf,
    extract_txt_records,
    parse_spf,
    spf_summary,
)
from host_triage.models import Status
from host_triage.target import parse_target


def test_extract_txt_records_joins_split_segments() -> None:
    # A long record dig returns as two adjacent quoted chunks on one line.
    output = '"v=spf1 include:a " "include:b -all"\n"unrelated=verification-token"\n'
    assert extract_txt_records(output) == [
        "v=spf1 include:a include:b -all",
        "unrelated=verification-token",
    ]


def test_extract_txt_records_ignores_unquoted_lines() -> None:
    output = 'cname-target.example.com.\n"v=spf1 -all"\n'
    assert extract_txt_records(output) == ["v=spf1 -all"]


def test_parse_spf_categorises_mechanisms() -> None:
    record = (
        "v=spf1 include:_spf.google.com include:spf.protection.outlook.com "
        "ip4:203.0.113.0/24 ip6:2001:db8::/32 a mx:mail.example.com "
        "exists:%{i}._spf.example.com ~all"
    )
    info = parse_spf(record)
    assert info["includes"] == ["_spf.google.com", "spf.protection.outlook.com"]
    assert info["ip4"] == ["203.0.113.0/24"]
    assert info["ip6"] == ["2001:db8::/32"]
    assert info["a"] == ["a"]
    assert info["mx"] == ["mx:mail.example.com"]
    assert info["exists"] == ["%{i}._spf.example.com"]
    assert info["all"] == "~all"
    assert info["redirect"] is None


def test_parse_spf_strips_qualifiers_and_reads_redirect() -> None:
    info = parse_spf("v=spf1 -ip4:198.51.100.7 redirect=_spf.example.net")
    assert info["ip4"] == ["198.51.100.7"]
    assert info["redirect"] == "_spf.example.net"
    assert info["all"] is None


def test_spf_summary_counts_and_all() -> None:
    info = parse_spf("v=spf1 include:a include:b ip4:1.2.3.0/24 -all")
    assert spf_summary(info) == "SPF: 2 include, 1 ip4 (-all)"


def test_check_spf_skips_without_dig(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    result = check_spf(parse_target("example.com"), CheckConfig())
    assert result.status is Status.SKIP


def _fake_run(stdout: str) -> object:
    def run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    return run


def test_check_spf_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(
        subprocess, "run", _fake_run('"v=spf1 include:_spf.google.com ip4:1.2.3.0/24 -all"\n')
    )
    result = check_spf(parse_target("example.com"), CheckConfig())
    assert result.status is Status.OK
    assert result.details["includes"] == ["_spf.google.com"]
    assert result.details["all"] == "-all"


def test_check_spf_warns_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(subprocess, "run", _fake_run('"some-other-txt=value"\n'))
    result = check_spf(parse_target("example.com"), CheckConfig())
    assert result.status is Status.WARN


def test_check_spf_warns_on_multiple(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr(
        subprocess, "run", _fake_run('"v=spf1 include:a -all"\n"v=spf1 include:b -all"\n')
    )
    result = check_spf(parse_target("example.com"), CheckConfig())
    assert result.status is Status.WARN
    assert "multiple" in result.summary


def test_spf_in_registry() -> None:
    assert "spf" in checks.REGISTRY
    assert "spf" not in checks.DEFAULT_CHECKS
