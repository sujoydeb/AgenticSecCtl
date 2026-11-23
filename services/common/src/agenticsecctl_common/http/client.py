"""Guarded HTTP client: validates every hop, connects to the pinned address."""
from __future__ import annotations

import contextlib
import http.client
import math
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urljoin

from .guard import Guard, SsrfRejected, Target, validate_url

Connector = Callable[[str, int, float], socket.socket]
MAX_REDIRECTS = 3  # PAR-F-10
_REDIRECT = {301, 302, 303, 307, 308}


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str


def _default_connector(ip: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((ip, port), timeout)


class _Pinned(http.client.HTTPConnection):
    def __init__(self, target: Target, ip: str, timeout: float, connector: Connector):
        super().__init__(target.host, target.port, timeout=timeout)
        self._ip, self._connector = ip, connector

    def connect(self) -> None:
        self.sock = self.tracked = self._connector(self._ip, self.port, float(self.timeout or 0))


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, target: Target, ip: str, timeout: float, connector: Connector):
        self._tls = ssl.create_default_context()
        super().__init__(target.host, target.port, timeout=timeout, context=self._tls)
        self._ip, self._connector = ip, connector

    def connect(self) -> None:
        raw = self._connector(self._ip, self.port, float(self.timeout or 0))
        # certificate and SNI are checked against the host name, not the pinned address
        self.sock = self.tracked = self._tls.wrap_socket(raw, server_hostname=self.host)


def _kill(conn: http.client.HTTPConnection) -> None:
    """Wake a thread blocked on this connection: shutdown makes a pending recv return, close alone may not."""
    # http.client forgets conn.sock once a "Connection: close" response starts, so use the reference kept at connect time
    sock = getattr(conn, "tracked", None) or conn.sock
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            sock.close()


def _expire(conn: http.client.HTTPConnection, fired: threading.Event) -> None:
    fired.set()
    _kill(conn)


class GuardedClient:
    def __init__(self, guard: Guard, connector: Connector = _default_connector):
        self._guard, self._connector = guard, connector

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                body: bytes | None = None, timeout: float = 10.0, max_bytes: int = 1_000_000,
                follow_redirects: bool = False, max_redirects: int = MAX_REDIRECTS,
                total_timeout: float | None = None) -> Response:
        """``timeout`` bounds each socket operation; ``total_timeout`` bounds the whole call (all hops, headers
        and body), so a server that drips bytes inside the per-read timeout cannot hold the caller (TC-Z2)."""
        if total_timeout is not None and not (math.isfinite(total_timeout) and total_timeout > 0):
            raise ValueError("total_timeout must be a positive number of seconds")
        deadline = None if total_timeout is None else time.monotonic() + total_timeout
        hops = 0
        while True:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise SsrfRejected("timeout")
            target = validate_url(url, self._guard)  # resolves once; every address checked
            ip = target.ips[0]
            cls = _PinnedTLS if target.scheme == "https" else _Pinned
            conn = cls(target, ip, timeout if remaining is None else min(timeout, remaining), self._connector)
            fired = threading.Event()
            timer = None
            if remaining is not None:
                timer = threading.Timer(remaining, _expire, args=(conn, fired))
                timer.daemon = True
                timer.start()
            try:
                conn.request(method, target.path, body=body,
                             headers={"User-Agent": "agent-gateway", **(headers or {})})
                resp = conn.getresponse()
                data = resp.read(max_bytes + 1)
                if fired.is_set():
                    raise SsrfRejected("timeout")
                if len(data) > max_bytes:
                    raise SsrfRejected("too-large")
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                status = resp.status
                declared = hdrs.get("content-length", "")
                # http.client returns what arrived when the peer closes early; a short body is a failure, not a result
                if declared.isdigit() and len(data) != int(declared) and method != "HEAD":
                    raise SsrfRejected("incomplete-body")
            except SsrfRejected:
                raise
            except Exception as exc:
                if fired.is_set() or (deadline is not None and time.monotonic() >= deadline - 0.05):
                    raise SsrfRejected("timeout") from None
                if isinstance(exc, http.client.HTTPException):  # garbage instead of HTTP: a stable reason, not a library error
                    raise SsrfRejected("protocol-error") from None
                raise
            finally:
                if timer is not None:
                    timer.cancel()
                conn.close()
            location = hdrs.get("location")
            if not (follow_redirects and status in _REDIRECT and location):
                return Response(status, hdrs, data, url)
            hops += 1
            if hops > min(max_redirects, MAX_REDIRECTS):
                raise SsrfRejected("redirect-limit")
            nxt = urljoin(url, location)
            if url.startswith("https:") and nxt.startswith("http:"):
                raise SsrfRejected("redirect-downgrade")
            url = nxt
            method, body = ("GET", None) if status in (301, 302, 303) else (method, body)
