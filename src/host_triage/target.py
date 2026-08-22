"""Parse a user-supplied target into a normalised host/port/scheme."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORT = 443
_SCHEME_PORTS = {"https": 443, "http": 80}


@dataclass(slots=True)
class Target:
    """A normalised target.

    ``scheme`` is empty when the user did not supply one (e.g. ``example.com``),
    in which case checks fall back to sensible defaults.
    """

    raw: str
    host: str
    port: int
    scheme: str = ""

    @property
    def is_tls(self) -> bool:
        return self.scheme == "https" or (self.scheme == "" and self.port == 443)

    @property
    def url(self) -> str:
        scheme = self.scheme or ("https" if self.port == 443 else "http")
        default = _SCHEME_PORTS.get(scheme)
        host = f"[{self.host}]" if ":" in self.host else self.host
        if default is not None and self.port == default:
            return f"{scheme}://{host}/"
        return f"{scheme}://{host}:{self.port}/"

    @property
    def hostport(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def parse_target(raw: str, *, default_port: int = DEFAULT_PORT) -> Target:
    """Parse ``raw`` into a :class:`Target`.

    Accepts ``example.com``, ``example.com:8443``, ``https://example.com``,
    ``http://example.com:8080/path`` and bracketed IPv6 like ``[::1]:443``.
    """
    value = raw.strip()
    if not value:
        raise ValueError("target must not be empty")

    if "://" in value:
        parts = urlsplit(value)
        host = parts.hostname
        if not host:
            raise ValueError(f"could not parse host from {raw!r}")
        scheme = parts.scheme.lower()
        try:
            explicit = parts.port
        except ValueError as exc:  # out-of-range port in the URL
            raise ValueError(f"invalid port in {raw!r}") from exc
        port = explicit or _SCHEME_PORTS.get(scheme, default_port)
        return Target(raw=raw, host=host, port=port, scheme=scheme)

    host, port = _split_host_port(value, default_port)
    return Target(raw=raw, host=host, port=port, scheme="")


def _split_host_port(value: str, default_port: int) -> tuple[str, int]:
    if value.startswith("["):  # bracketed IPv6, optionally with :port
        end = value.find("]")
        if end == -1:
            raise ValueError(f"invalid bracketed address {value!r}")
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest:
            return host, default_port
        if rest.startswith(":"):
            return host, _parse_port(rest[1:])
        raise ValueError(f"unexpected trailing text in {value!r}")

    if value.count(":") == 1:  # host:port (a bare IPv6 has >1 colon)
        host, _, port_s = value.partition(":")
        if not host:
            raise ValueError(f"missing host in {value!r}")
        return host, _parse_port(port_s)

    return value, default_port  # bare hostname or bare IPv6 without a port


def _parse_port(text: str) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise ValueError(f"port must be an integer, got {text!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range (1-65535): {port}")
    return port
