from __future__ import annotations

import urllib.error
import urllib.request
from email.message import Message

import pytest

from host_triage import checks
from host_triage.checks import (
    HSTS_MIN_MAX_AGE,
    CheckConfig,
    audit_security_headers,
    check_headers,
    parse_hsts_max_age,
)
from host_triage.models import Status
from host_triage.target import parse_target

FULL_SET = {
    "Strict-Transport-Security": f"max-age={HSTS_MIN_MAX_AGE}; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def test_audit_all_present_is_clean() -> None:
    audit = audit_security_headers(dict(FULL_SET), tls=True)
    assert audit.missing == []
    assert audit.weak == []
    assert audit.checked == 5
    assert audit.status is Status.OK


def test_audit_is_case_insensitive_about_header_names() -> None:
    lowered = {k.lower(): v for k, v in FULL_SET.items()}
    assert audit_security_headers(lowered, tls=True).status is Status.OK


def test_audit_reports_missing_headers() -> None:
    audit = audit_security_headers({"X-Frame-Options": "DENY"}, tls=True)
    assert audit.present == ["X-Frame-Options"]
    assert "CSP" in audit.missing
    assert "HSTS" in audit.missing
    assert audit.status is Status.WARN


def test_audit_skips_hsts_over_plain_http() -> None:
    # HSTS is meaningless without TLS, so it is neither present nor missing.
    audit = audit_security_headers({}, tls=False)
    assert "HSTS" not in audit.missing
    assert audit.checked == 4


def test_audit_flags_short_hsts_max_age() -> None:
    headers = {**FULL_SET, "Strict-Transport-Security": "max-age=300"}
    audit = audit_security_headers(headers, tls=True)
    assert audit.missing == []
    assert len(audit.weak) == 1
    assert "max-age=300" in audit.weak[0]
    assert audit.status is Status.WARN


def test_audit_flags_hsts_without_max_age() -> None:
    headers = {**FULL_SET, "Strict-Transport-Security": "includeSubDomains"}
    audit = audit_security_headers(headers, tls=True)
    assert "no max-age" in audit.weak[0]


def test_audit_flags_wrong_nosniff_value() -> None:
    headers = {**FULL_SET, "X-Content-Type-Options": "sniff"}
    audit = audit_security_headers(headers, tls=True)
    assert "expected 'nosniff'" in audit.weak[0]
    assert audit.status is Status.WARN


def test_audit_accepts_nosniff_with_odd_casing_and_spacing() -> None:
    headers = {**FULL_SET, "X-Content-Type-Options": "  NoSniff "}
    assert audit_security_headers(headers, tls=True).weak == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000", 31536000),
        ("max-age=0", 0),
        ('max-age="31536000"; includeSubDomains', 31536000),
        ("MAX-AGE = 600 ; preload", 600),
        ("includeSubDomains", None),
    ],
)
def test_parse_hsts_max_age(value: str, expected: int | None) -> None:
    assert parse_hsts_max_age(value) == expected


def test_audit_summary_lists_what_is_missing() -> None:
    audit = audit_security_headers({}, tls=True)
    assert audit.summary.startswith("0 of 5 security header(s) present")
    assert "missing: HSTS" in audit.summary


def _as_message(headers: dict[str, str]) -> Message:
    """urllib hands back an email.Message, not a plain dict."""
    message = Message()
    for name, value in headers.items():
        message[name] = value
    return message


class _FakeResponse:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = _as_message(headers)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def test_check_headers_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: _FakeResponse(dict(FULL_SET)))
    result = check_headers(parse_target("https://example.com"), CheckConfig())
    assert result.status is Status.OK
    assert result.details["missing"] == []


def test_check_headers_warns_on_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: _FakeResponse({}))
    result = check_headers(parse_target("https://example.com"), CheckConfig())
    assert result.status is Status.WARN
    assert len(result.details["missing"]) == 5  # type: ignore[arg-type]


def test_check_headers_audits_error_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    # A 403 still carries headers worth auditing, so don't throw the response away.
    def raise_http_error(*_a: object, **_k: object) -> None:
        raise urllib.error.HTTPError(
            "https://example.com", 403, "Forbidden", _as_message(FULL_SET), None
        )

    monkeypatch.setattr(urllib.request, "urlopen", raise_http_error)
    result = check_headers(parse_target("https://example.com"), CheckConfig())
    assert result.status is Status.OK
    assert result.details["missing"] == []
    assert len(result.details["present"]) == 5  # type: ignore[arg-type]


def test_check_headers_fails_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_url_error(*_a: object, **_k: object) -> None:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", raise_url_error)
    result = check_headers(parse_target("https://example.com"), CheckConfig())
    assert result.status is Status.FAIL
    assert "request failed" in result.summary


def test_check_headers_fails_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_timeout(*_a: object, **_k: object) -> None:
        raise TimeoutError

    monkeypatch.setattr(urllib.request, "urlopen", raise_timeout)
    assert check_headers(parse_target("https://example.com"), CheckConfig()).status is Status.FAIL


def test_headers_in_registry() -> None:
    assert "headers" in checks.REGISTRY
    assert "headers" not in checks.DEFAULT_CHECKS
