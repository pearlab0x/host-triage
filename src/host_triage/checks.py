"""Individual triage checks and the registry that ties them together.

Each check is a callable ``(Target, CheckConfig) -> CheckResult``. Network I/O
is deliberately thin so that the classification logic (which is where bugs
hide) lives in small, pure, unit-testable helpers.
"""

from __future__ import annotations

import http
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from .models import CheckResult, Status
from .target import Target

Check = Callable[["Target", "CheckConfig"], CheckResult]


@dataclass(slots=True)
class CheckConfig:
    timeout: float = 5.0
    tls_warn_days: int = 21
    http_method: str = "GET"
    ping_count: int = 3
    trace_max_hops: int = 20
    user_agent: str = "host-triage"


# --------------------------------------------------------------------------- #
# timing helper
# --------------------------------------------------------------------------- #
class _Timer:
    __slots__ = ("_start", "elapsed_ms")

    def __enter__(self) -> _Timer:
        self._start = time.perf_counter()
        self.elapsed_ms = 0.0
        return self

    def __exit__(self, *_: object) -> None:
        self.elapsed_ms = (time.perf_counter() - self._start) * 1000.0


# --------------------------------------------------------------------------- #
# dns
# --------------------------------------------------------------------------- #
def check_dns(target: Target, cfg: CheckConfig) -> CheckResult:
    with _Timer() as t:
        try:
            infos = socket.getaddrinfo(target.host, target.port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            return CheckResult(
                "dns",
                Status.FAIL,
                f"resolution failed: {exc.strerror or exc}",
                duration_ms=t.elapsed_ms,
            )
    addrs = _unique_addresses(infos)
    shown = ", ".join(addrs[:3]) + (", …" if len(addrs) > 3 else "")
    return CheckResult(
        "dns",
        Status.OK,
        f"resolved {len(addrs)} address{'es' if len(addrs) != 1 else ''} ({shown})",
        details={"addresses": addrs},
        duration_ms=t.elapsed_ms,
    )


def _unique_addresses(infos: list) -> list[str]:  # type: ignore[type-arg]
    seen: dict[str, None] = {}
    for info in infos:
        ip = info[4][0]
        seen.setdefault(ip, None)
    return list(seen)


# --------------------------------------------------------------------------- #
# tcp
# --------------------------------------------------------------------------- #
def check_tcp(target: Target, cfg: CheckConfig) -> CheckResult:
    with _Timer() as t:
        try:
            with socket.create_connection((target.host, target.port), timeout=cfg.timeout) as sock:
                peer = sock.getpeername()[0]
        except TimeoutError:
            return CheckResult(
                "tcp",
                Status.FAIL,
                f"connect to {target.hostport} timed out",
                duration_ms=t.elapsed_ms,
            )
        except OSError as exc:
            return CheckResult(
                "tcp",
                Status.FAIL,
                f"connect to {target.hostport} failed: {exc.strerror or exc}",
                duration_ms=t.elapsed_ms,
            )
    return CheckResult(
        "tcp",
        Status.OK,
        f"connected to {peer}:{target.port}",
        details={"peer": peer, "port": target.port},
        duration_ms=t.elapsed_ms,
    )


# --------------------------------------------------------------------------- #
# tls
# --------------------------------------------------------------------------- #
def check_tls(target: Target, cfg: CheckConfig) -> CheckResult:
    if not target.is_tls and target.scheme == "http":
        return CheckResult("tls", Status.SKIP, "target is plain http")
    with _Timer() as t:
        ctx = ssl.create_default_context()
        try:
            with (
                socket.create_connection((target.host, target.port), timeout=cfg.timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=target.host) as ssock,
            ):
                cert = ssock.getpeercert() or {}
        except ssl.SSLCertVerificationError as exc:
            return CheckResult(
                "tls",
                Status.FAIL,
                f"certificate invalid: {exc.verify_message or exc.reason}",
                details={"reason": exc.reason},
                duration_ms=t.elapsed_ms,
            )
        except ssl.SSLError as exc:
            return CheckResult(
                "tls",
                Status.FAIL,
                f"tls handshake failed: {exc.reason or exc}",
                duration_ms=t.elapsed_ms,
            )
        except TimeoutError:
            return CheckResult(
                "tls", Status.FAIL, "tls handshake timed out", duration_ms=t.elapsed_ms
            )
        except OSError as exc:
            return CheckResult(
                "tls",
                Status.FAIL,
                f"connection failed: {exc.strerror or exc}",
                duration_ms=t.elapsed_ms,
            )

    not_after = str(cert.get("notAfter", ""))
    try:
        expiry = parse_cert_datetime(not_after)
    except ValueError:
        return CheckResult(
            "tls",
            Status.WARN,
            "connected but certificate expiry could not be parsed",
            duration_ms=t.elapsed_ms,
        )
    days_left = (expiry - datetime.now(UTC)).days
    status = classify_cert_days(days_left, cfg.tls_warn_days)
    issuer = _cert_field(cert.get("issuer"), "organizationName") or _cert_field(
        cert.get("issuer"), "commonName"
    )
    summary = _tls_summary(days_left, expiry)
    return CheckResult(
        "tls",
        status,
        summary,
        details={
            "days_left": days_left,
            "not_after": expiry.date().isoformat(),
            "issuer": issuer,
        },
        duration_ms=t.elapsed_ms,
    )


def parse_cert_datetime(value: str) -> datetime:
    """Parse OpenSSL's ``notAfter`` format, e.g. ``Aug 31 23:59:59 2026 GMT``."""
    if not value:
        raise ValueError("empty certificate date")
    dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")  # noqa: DTZ007 - tz is GMT/UTC
    return dt.replace(tzinfo=UTC)


def classify_cert_days(days_left: int, warn_days: int) -> Status:
    if days_left < 0:
        return Status.FAIL
    if days_left <= warn_days:
        return Status.WARN
    return Status.OK


def _tls_summary(days_left: int, expiry: datetime) -> str:
    date = expiry.date().isoformat()
    if days_left < 0:
        return f"certificate expired {abs(days_left)} day(s) ago ({date})"
    return f"certificate valid, expires in {days_left} day(s) ({date})"


def _cert_field(rdns: object, key: str) -> str | None:
    if not isinstance(rdns, tuple):
        return None
    for rdn in rdns:
        for pair in rdn:
            if isinstance(pair, tuple) and len(pair) == 2 and pair[0] == key:
                return str(pair[1])
    return None


# --------------------------------------------------------------------------- #
# http
# --------------------------------------------------------------------------- #
def check_http(target: Target, cfg: CheckConfig) -> CheckResult:
    url = target.url
    if not url.startswith(("http://", "https://")):
        return CheckResult("http", Status.SKIP, f"unsupported scheme for {url}")
    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        url, method=cfg.http_method, headers={"User-Agent": cfg.user_agent}
    )
    with _Timer() as t:
        try:
            with urllib.request.urlopen(request, timeout=cfg.timeout) as resp:  # noqa: S310
                status = resp.status
                final = resp.geturl()
                resp.read(2048)
        except urllib.error.HTTPError as exc:
            status = exc.code
            final = exc.url or url
        except urllib.error.URLError as exc:
            return CheckResult(
                "http", Status.FAIL, f"request failed: {exc.reason}", duration_ms=t.elapsed_ms
            )
        except TimeoutError:
            return CheckResult("http", Status.FAIL, "request timed out", duration_ms=t.elapsed_ms)
    result_status = classify_http_status(status)
    reason = _http_reason(status)
    redirected = final != url
    summary = f"{status} {reason}" + (f" -> {final}" if redirected else "")
    return CheckResult(
        "http",
        result_status,
        summary,
        details={"status": status, "final_url": final},
        duration_ms=t.elapsed_ms,
    )


def classify_http_status(status: int) -> Status:
    if status >= 500:
        return Status.FAIL
    if status >= 400:
        return Status.WARN
    return Status.OK


def _http_reason(status: int) -> str:
    try:
        return http.HTTPStatus(status).phrase
    except ValueError:
        return ""


# --------------------------------------------------------------------------- #
# ping (shells out to the system binary; ICMP raw sockets need root)
# --------------------------------------------------------------------------- #
def check_ping(target: Target, cfg: CheckConfig) -> CheckResult:
    binary = shutil.which("ping")
    if binary is None:
        return CheckResult("ping", Status.SKIP, "ping binary not found on PATH")
    argv = _ping_argv(binary, target.host, cfg.ping_count, cfg.timeout)
    with _Timer() as t:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=cfg.timeout * cfg.ping_count + 2,
            )
        except subprocess.TimeoutExpired:
            return CheckResult("ping", Status.FAIL, "ping timed out", duration_ms=t.elapsed_ms)
    if proc.returncode != 0:
        return CheckResult(
            "ping", Status.FAIL, f"{target.host} unreachable", duration_ms=t.elapsed_ms
        )
    avg = parse_ping_rtt(proc.stdout)
    summary = f"reachable, avg {avg:.1f} ms" if avg is not None else "reachable"
    details: dict[str, object] = {"avg_rtt_ms": avg} if avg is not None else {}
    return CheckResult("ping", Status.OK, summary, details=details, duration_ms=t.elapsed_ms)


def _ping_argv(binary: str, host: str, count: int, timeout: float) -> list[str]:
    if sys.platform == "win32":
        return [binary, "-n", str(count), "-w", str(int(timeout * 1000)), host]
    if sys.platform == "darwin":
        return [binary, "-c", str(count), "-t", str(max(1, int(timeout))), host]
    return [binary, "-c", str(count), "-w", str(max(1, int(timeout))), host]


_RTT_UNIX = re.compile(r"=\s*[\d.]+/([\d.]+)/[\d.]+")
_RTT_WIN = re.compile(r"Average\s*=\s*(\d+)\s*ms", re.IGNORECASE)


def parse_ping_rtt(output: str) -> float | None:
    """Extract the average round-trip time in milliseconds, if present."""
    match = _RTT_UNIX.search(output)
    if match:
        return float(match.group(1))
    match = _RTT_WIN.search(output)
    if match:
        return float(match.group(1))
    return None


# --------------------------------------------------------------------------- #
# traceroute (opt-in; slow)
# --------------------------------------------------------------------------- #
def check_trace(target: Target, cfg: CheckConfig) -> CheckResult:
    name = "tracert" if sys.platform == "win32" else "traceroute"
    binary = shutil.which(name)
    if binary is None:
        return CheckResult("trace", Status.SKIP, f"{name} not found on PATH")
    if sys.platform == "win32":
        argv = [binary, "-h", str(cfg.trace_max_hops), target.host]
    else:
        argv = [binary, "-m", str(cfg.trace_max_hops), "-n", target.host]
    with _Timer() as t:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv, capture_output=True, text=True, timeout=cfg.trace_max_hops * 2 + 10
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                "trace", Status.WARN, "traceroute timed out", duration_ms=t.elapsed_ms
            )
    hops = count_trace_hops(proc.stdout)
    return CheckResult(
        "trace",
        Status.OK,
        f"{hops} hop(s) to {target.host}",
        details={"hops": hops},
        duration_ms=t.elapsed_ms,
    )


def count_trace_hops(output: str) -> int:
    hops = 0
    for line in output.splitlines():
        if re.match(r"\s*\d+\s", line):
            hops += 1
    return hops


# --------------------------------------------------------------------------- #
# registry
# --------------------------------------------------------------------------- #
REGISTRY: dict[str, Check] = {
    "dns": check_dns,
    "ping": check_ping,
    "tcp": check_tcp,
    "tls": check_tls,
    "http": check_http,
    "trace": check_trace,
}

DEFAULT_CHECKS: tuple[str, ...] = ("dns", "ping", "tcp", "tls", "http")


def resolve_checks(names: list[str]) -> list[str]:
    """Validate requested check names, preserving registry order."""
    unknown = [n for n in names if n not in REGISTRY]
    if unknown:
        valid = ", ".join(REGISTRY)
        raise ValueError(f"unknown check(s): {', '.join(unknown)} (valid: {valid})")
    wanted = set(names)
    return [name for name in REGISTRY if name in wanted]
