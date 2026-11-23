"""URL and address validation for the SSRF guard.

Every outbound URL is normalised, resolved, and every returned address is
checked; the caller connects to a validated address (resolve-then-pin).
Exceptions are explicit entries scoped to one host and port, with an owner,
a reason, an expiry and the environments where they apply (FR-SSRF-5); they
are configuration, never a code path that skips the guard.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

Resolver = Callable[[str, int], list[str]]


class SsrfRejected(Exception):
    """Raised with a stable reason code; the message never echoes the input."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ExceptionEntry:
    host: str
    port: int
    owner: str
    reason: str
    expires_at: datetime | None
    environments: frozenset[str]

    def __post_init__(self):
        if not self.owner.strip() or not self.reason.strip():
            raise ValueError("exception entry needs an owner and a reason")
        if self.expires_at is None or self.expires_at.tzinfo is None:
            raise ValueError("exception entry needs a timezone-aware expiry")
        if not self.environments:
            raise ValueError("exception entry needs at least one environment")


@dataclass(frozen=True)
class Guard:
    resolver: Resolver = field(default=None)  # type: ignore[assignment]
    exceptions: tuple[ExceptionEntry, ...] = ()
    environment: str = "production"
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def __post_init__(self):
        if self.resolver is None:
            object.__setattr__(self, "resolver", system_resolver)


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str  # path plus query
    ips: tuple[str, ...]


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


BLOCKED_HOSTS = frozenset({"localhost", "metadata", "metadata.google.internal", "instance-data",
                           "instance-data.ec2.internal", "metadata.azure.com"})
_EXTRA_V6 = [ipaddress.ip_network(n)
             for n in ("::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")]
_DOT_VARIANTS = dict.fromkeys(map(ord, "。．｡"), ".")
_NUMERIC = re.compile(r"^(0[xX][0-9a-fA-F]*|[0-9]+)$")
_HEX = re.compile(r"^0[xX][0-9a-fA-F]+$")
_OCT = re.compile(r"^0[0-7]*$")
_DEC = re.compile(r"^[1-9][0-9]*$")
_BAD_HOST_CHARS = re.compile(r"[\s\x00-\x1f\x7f%\\/?#@\[\]]")


def blocked_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return blocked_reason(ip.ipv4_mapped)
        if any(ip in n for n in _EXTRA_V6) or ip.sixtofour or ip.teredo:
            return "blocked-address"
    if (ip.is_multicast or ip.is_reserved or ip.is_private or ip.is_link_local
            or ip.is_loopback or ip.is_unspecified):
        return "blocked-address"
    return None if ip.is_global else "blocked-address"


def _legacy_ipv4(host: str) -> str:
    """inet_aton semantics (decimal, octal, hex, 1 to 4 parts) -> dotted quad."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        raise SsrfRejected("malformed")
    nums = []
    for p in parts:
        if _HEX.match(p):
            nums.append(int(p, 16))
        elif _OCT.match(p):
            nums.append(int(p, 8))
        elif _DEC.match(p):
            nums.append(int(p, 10))
        else:
            raise SsrfRejected("malformed")
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(parts)):
        raise SsrfRejected("malformed")
    value = last
    for i, n in enumerate(head):
        value += n << (8 * (3 - i))
    return str(ipaddress.IPv4Address(value))


def normalize_host(raw: str) -> tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
    """Return (canonical host, ip if the host is an address literal)."""
    if raw.startswith("["):
        if not raw.endswith("]") or "%" in raw:
            raise SsrfRejected("malformed")
        try:
            ip6 = ipaddress.IPv6Address(raw[1:-1])
        except ValueError:
            raise SsrfRejected("malformed") from None
        return str(ip6), ip6
    host = unicodedata.normalize("NFKC", raw).translate(_DOT_VARIANTS).lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or _BAD_HOST_CHARS.search(host):
        raise SsrfRejected("malformed")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise SsrfRejected("malformed") from None
    if _NUMERIC.match(host.rsplit(".", 1)[-1]):
        ip4 = ipaddress.IPv4Address(_legacy_ipv4(host))
        return str(ip4), ip4
    return host, None


def _find_exception(guard: Guard, host: str, port: int) -> tuple[ExceptionEntry | None, bool]:
    """Return (matching entry, expired-or-out-of-scope flag)."""
    now = guard.clock()
    for e in guard.exceptions:
        if e.host == host and e.port == port and guard.environment in e.environments:
            return (e, False) if now < e.expires_at else (None, True)
    return None, False


def validate_url(url: str, guard: Guard) -> Target:
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url) or "\\" in url:
        raise SsrfRejected("malformed")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise SsrfRejected("malformed") from None
    if parts.scheme not in ("http", "https"):
        raise SsrfRejected("scheme")
    if not parts.netloc or "@" in parts.netloc:
        raise SsrfRejected("userinfo" if "@" in parts.netloc else "malformed")
    raw_host = parts.netloc.rsplit(":", 1)[0] if port is not None else parts.netloc
    host, ip = normalize_host(raw_host)
    port = port or (443 if parts.scheme == "https" else 80)
    entry, _ = _find_exception(guard, host, port)
    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")

    if entry is None and (host in BLOCKED_HOSTS or host.endswith(".localhost")):
        raise SsrfRejected("blocked-host")
    if ip is not None:
        ips = [str(ip)]
    else:
        try:
            ips = guard.resolver(host, port)
        except OSError:
            raise SsrfRejected("resolve-failed") from None
        if not ips:
            raise SsrfRejected("resolve-failed")
    validated = []
    for text in ips:
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            raise SsrfRejected("malformed") from None
        if entry is None and blocked_reason(addr):
            raise SsrfRejected("blocked-address")
        validated.append(str(addr))
    return Target(parts.scheme, host, port, path, tuple(validated))
