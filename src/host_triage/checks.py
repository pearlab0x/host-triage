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
# spf (TXT lookup; shells out to dig, which handles resolver config and TCP)
# --------------------------------------------------------------------------- #
def check_spf(target: Target, cfg: CheckConfig) -> CheckResult:
    binary = shutil.which("dig")
    if binary is None:
        return CheckResult("spf", Status.SKIP, "dig not found on PATH (needed for TXT lookup)")
    argv = [binary, "+short", f"+time={max(1, int(cfg.timeout))}", "+tries=1", "TXT", target.host]
    with _Timer() as t:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv, capture_output=True, text=True, timeout=cfg.timeout + 2
            )
        except subprocess.TimeoutExpired:
            return CheckResult("spf", Status.FAIL, "TXT lookup timed out", duration_ms=t.elapsed_ms)

    txt_records = extract_txt_records(proc.stdout)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return CheckResult(
            "spf",
            Status.WARN,
            "no SPF record found",
            details={"txt_records": len(txt_records)},
            duration_ms=t.elapsed_ms,
        )
    if len(spf_records) > 1:
        return CheckResult(
            "spf",
            Status.WARN,
            f"multiple SPF records found ({len(spf_records)}); RFC 7208 permits only one",
            details={"records": spf_records},
            duration_ms=t.elapsed_ms,
        )

    record = spf_records[0]
    info = parse_spf(record)
    return CheckResult(
        "spf",
        Status.OK,
        spf_summary(info),
        details={"record": record, **info},
        duration_ms=t.elapsed_ms,
    )


def extract_txt_records(output: str) -> list[str]:
    """Turn ``dig +short TXT`` output into a list of full TXT strings.

    Each line may hold one record split into several quoted segments; per RFC
    those segments are concatenated with no separator. Lines without quotes
    (e.g. a chased CNAME target) are ignored.
    """
    records: list[str] = []
    for line in output.splitlines():
        segments = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        if segments:
            records.append("".join(segments))
    return records


def parse_spf(record: str) -> dict[str, object]:
    """Break an SPF record into its mechanisms and modifiers."""
    includes: list[str] = []
    ip4: list[str] = []
    ip6: list[str] = []
    a: list[str] = []
    mx: list[str] = []
    exists: list[str] = []
    other: list[str] = []
    redirect: str | None = None
    all_qualifier: str | None = None

    for token in record.split()[1:]:  # skip the leading "v=spf1"
        mech = token
        qualifier = "+"
        if mech[:1] in "+-~?":
            qualifier, mech = mech[0], mech[1:]
        low = mech.lower()
        if low == "all":
            all_qualifier = qualifier + "all"
        elif low.startswith("include:"):
            includes.append(mech.split(":", 1)[1])
        elif low.startswith("ip4:"):
            ip4.append(mech.split(":", 1)[1])
        elif low.startswith("ip6:"):
            ip6.append(mech.split(":", 1)[1])
        elif low == "a" or low.startswith(("a:", "a/")):
            a.append(mech)
        elif low == "mx" or low.startswith(("mx:", "mx/")):
            mx.append(mech)
        elif low.startswith("exists:"):
            exists.append(mech.split(":", 1)[1])
        elif low.startswith("redirect="):
            redirect = mech.split("=", 1)[1]
        else:
            other.append(mech)

    return {
        "includes": includes,
        "ip4": ip4,
        "ip6": ip6,
        "a": a,
        "mx": mx,
        "exists": exists,
        "redirect": redirect,
        "all": all_qualifier,
        "other": other,
    }


def spf_summary(info: dict[str, object]) -> str:
    parts: list[str] = []
    for key, label in (
        ("includes", "include"),
        ("ip4", "ip4"),
        ("ip6", "ip6"),
        ("a", "a"),
        ("mx", "mx"),
        ("exists", "exists"),
    ):
        values = info[key]
        if isinstance(values, list) and values:
            parts.append(f"{len(values)} {label}")
    if info["redirect"]:
        parts.append(f"redirect={info['redirect']}")
    summary = "SPF: " + (", ".join(parts) if parts else "no mechanisms")
    if info["all"]:
        summary += f" ({info['all']})"
    return summary


# --------------------------------------------------------------------------- #
# dmarc (TXT lookup at _dmarc.<domain>; sibling of the spf check)
# --------------------------------------------------------------------------- #
def check_dmarc(target: Target, cfg: CheckConfig) -> CheckResult:
    binary = shutil.which("dig")
    if binary is None:
        return CheckResult("dmarc", Status.SKIP, "dig not found on PATH (needed for TXT lookup)")
    name = f"_dmarc.{target.host}"
    argv = [binary, "+short", f"+time={max(1, int(cfg.timeout))}", "+tries=1", "TXT", name]
    with _Timer() as t:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv, capture_output=True, text=True, timeout=cfg.timeout + 2
            )
        except subprocess.TimeoutExpired:
            return CheckResult(
                "dmarc", Status.FAIL, "TXT lookup timed out", duration_ms=t.elapsed_ms
            )

    txt_records = extract_txt_records(proc.stdout)
    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return CheckResult(
            "dmarc",
            Status.WARN,
            f"no DMARC record found at {name}",
            details={"queried": name},
            duration_ms=t.elapsed_ms,
        )
    if len(dmarc_records) > 1:
        return CheckResult(
            "dmarc",
            Status.WARN,
            f"multiple DMARC records found ({len(dmarc_records)}); RFC 7489 permits only one",
            details={"queried": name, "records": dmarc_records},
            duration_ms=t.elapsed_ms,
        )

    record = dmarc_records[0]
    info = parse_dmarc(record)
    return CheckResult(
        "dmarc",
        classify_dmarc(info),
        dmarc_summary(info),
        details={"queried": name, "record": record, **info},
        duration_ms=t.elapsed_ms,
    )


_DMARC_URI_TAGS = ("rua", "ruf")


def parse_dmarc(record: str) -> dict[str, object]:
    """Break a DMARC record into its tags.

    Tags are ``;``-separated ``key=value`` pairs. ``rua``/``ruf`` hold
    comma-separated URI lists; ``pct``/``ri`` are numeric. Keys are
    case-insensitive per RFC 7489, values are kept as written.
    """
    tags: dict[str, object] = {}
    for chunk in record.split(";"):
        key, sep, value = chunk.partition("=")
        key = key.strip().lower()
        if not sep or not key or key == "v":
            continue
        value = value.strip()
        if key in _DMARC_URI_TAGS:
            tags[key] = [uri.strip() for uri in value.split(",") if uri.strip()]
        elif key in ("pct", "ri"):
            try:
                tags[key] = int(value)
            except ValueError:
                tags[key] = value
        else:
            tags[key] = value.lower() if key in ("p", "sp", "adkim", "aspf") else value
    return tags


def classify_dmarc(info: dict[str, object]) -> Status:
    """A record that does not actually enforce anything is a warning, not a pass."""
    policy = info.get("p")
    if policy not in ("quarantine", "reject"):
        return Status.WARN
    pct = info.get("pct")
    if isinstance(pct, int) and pct < 100:
        return Status.WARN
    return Status.OK


def dmarc_summary(info: dict[str, object]) -> str:
    policy = info.get("p")
    if not policy:
        return "DMARC record present but has no policy (p=) tag"
    if policy == "none":
        parts = ["policy p=none (monitor only, nothing enforced)"]
    else:
        parts = [f"policy p={policy}"]
    if info.get("sp"):
        parts.append(f"sp={info['sp']}")
    pct = info.get("pct")
    if isinstance(pct, int) and pct < 100:
        parts.append(f"pct={pct} (applied to {pct}% of mail)")
    for tag in _DMARC_URI_TAGS:
        uris = info.get(tag)
        if isinstance(uris, list) and uris:
            parts.append(f"{len(uris)} {tag}")
    return "DMARC: " + ", ".join(parts)


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
    "spf": check_spf,
    "dmarc": check_dmarc,
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
