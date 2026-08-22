from __future__ import annotations

import pytest

from host_triage.target import Target, parse_target


@pytest.mark.parametrize(
    ("raw", "host", "port", "scheme"),
    [
        ("example.com", "example.com", 443, ""),
        ("example.com:8443", "example.com", 8443, ""),
        ("https://example.com", "example.com", 443, "https"),
        ("http://example.com", "example.com", 80, "http"),
        ("https://example.com:8443/path", "example.com", 8443, "https"),
        ("http://api.local:8080", "api.local", 8080, "http"),
        ("[2606:4700:4700::1111]:853", "2606:4700:4700::1111", 853, ""),
        ("2606:4700:4700::1111", "2606:4700:4700::1111", 443, ""),
        ("https://[::1]:9443/", "::1", 9443, "https"),
    ],
)
def test_parse_target_variants(raw: str, host: str, port: int, scheme: str) -> None:
    target = parse_target(raw)
    assert target.host == host
    assert target.port == port
    assert target.scheme == scheme


def test_default_port_override() -> None:
    assert parse_target("example.com", default_port=80).port == 80


@pytest.mark.parametrize("raw", ["", "   ", "example.com:0", "example.com:70000", "example.com:abc"])
def test_parse_target_rejects_bad_input(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_target(raw)


def test_url_default_https() -> None:
    assert parse_target("example.com").url == "https://example.com/"


def test_url_keeps_nondefault_port() -> None:
    assert parse_target("http://example.com:8080").url == "http://example.com:8080/"


def test_url_brackets_ipv6() -> None:
    assert parse_target("https://[::1]").url == "https://[::1]/"


def test_is_tls() -> None:
    assert parse_target("example.com").is_tls is True
    assert parse_target("http://example.com").is_tls is False
    assert Target(raw="x", host="x", port=443, scheme="").is_tls is True
