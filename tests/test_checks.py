from __future__ import annotations

import socket
from datetime import UTC, datetime

import pytest

from host_triage import checks
from host_triage.checks import (
    classify_cert_days,
    classify_http_status,
    count_trace_hops,
    parse_cert_datetime,
    parse_ping_rtt,
    resolve_checks,
)
from host_triage.models import Status
from host_triage.target import parse_target

_AddrInfo = tuple[int, int, int, str, tuple[str, int]]


@pytest.mark.parametrize(
    ("status", "expected"),
    [(200, Status.OK), (301, Status.OK), (399, Status.OK), (404, Status.WARN), (500, Status.FAIL)],
)
def test_classify_http_status(status: int, expected: Status) -> None:
    assert classify_http_status(status) is expected


@pytest.mark.parametrize(
    ("days", "warn", "expected"),
    [(-1, 21, Status.FAIL), (0, 21, Status.WARN), (21, 21, Status.WARN), (22, 21, Status.OK)],
)
def test_classify_cert_days(days: int, warn: int, expected: Status) -> None:
    assert classify_cert_days(days, warn) is expected


def test_parse_cert_datetime() -> None:
    dt = parse_cert_datetime("Aug 31 23:59:59 2026 GMT")
    assert dt == datetime(2026, 8, 31, 23, 59, 59, tzinfo=UTC)


def test_parse_cert_datetime_rejects_junk() -> None:
    with pytest.raises(ValueError):
        parse_cert_datetime("not a date")


LINUX_PING = "rtt min/avg/max/mdev = 8.123/9.456/10.789/0.900 ms"
MAC_PING = "round-trip min/avg/max/stddev = 8.1/9.4/10.7/0.9 ms"
WIN_PING = "Minimum = 8ms, Maximum = 10ms, Average = 9ms"


@pytest.mark.parametrize(
    ("output", "expected"),
    [(LINUX_PING, 9.456), (MAC_PING, 9.4), (WIN_PING, 9.0), ("no timing here", None)],
)
def test_parse_ping_rtt(output: str, expected: float | None) -> None:
    assert parse_ping_rtt(output) == expected


def test_count_trace_hops() -> None:
    output = " 1  10.0.0.1  1.1 ms\n 2  93.184.216.34  9.9 ms\nheader line\n 3  * * *\n"
    assert count_trace_hops(output) == 3


def test_resolve_checks_orders_by_registry() -> None:
    assert resolve_checks(["http", "dns"]) == ["dns", "http"]


def test_resolve_checks_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown check"):
        resolve_checks(["dns", "bogus"])


def test_check_dns_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, port: int, **_: object) -> list[_AddrInfo]:
        return [
            (0, 0, 0, "", ("93.184.216.34", 443)),
            (0, 0, 0, "", ("93.184.216.34", 443)),  # duplicate is de-duped
            (0, 0, 0, "", ("2606:2800:220:1:248:1893:25c8:1946", 443)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = checks.check_dns(parse_target("example.com"), checks.CheckConfig())
    assert result.status is Status.OK
    assert result.details["addresses"] == [
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
    ]


def test_check_dns_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: object, **__: object) -> list[_AddrInfo]:
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    result = checks.check_dns(parse_target("nope.invalid"), checks.CheckConfig())
    assert result.status is Status.FAIL
