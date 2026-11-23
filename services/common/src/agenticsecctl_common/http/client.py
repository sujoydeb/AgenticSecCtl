"""Guarded HTTP client: validates every hop, connects to the pinned address."""
from __future__ import annotations

import http.client
import socket
import ssl
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

    def connect(self):
        self.sock = self._connector(self._ip, self.port, self.timeout)


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, target: Target, ip: str, timeout: float, connector: Connector):
        super().__init__(target.host, target.port, timeout=timeout, context=ssl.create_default_context())
        self._ip, self._connector = ip, connector

    def connect(self):
        raw = self._connector(self._ip, self.port, self.timeout)
        # certificate and SNI are checked against the host name, not the pinned address
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class GuardedClient:
    def __init__(self, guard: Guard, connector: Connector = _default_connector):
        self._guard, self._connector = guard, connector

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                body: bytes | None = None, timeout: float = 10.0, max_bytes: int = 1_000_000,
                follow_redirects: bool = False, max_redirects: int = MAX_REDIRECTS) -> Response:
        hops = 0
        while True:
            target = validate_url(url, self._guard)  # resolves once; every address checked
            ip = target.ips[0]
            cls = _PinnedTLS if target.scheme == "https" else _Pinned
            conn = cls(target, ip, timeout, self._connector)
            try:
                conn.request(method, target.path, body=body,
                             headers={"User-Agent": "agent-gateway", **(headers or {})})
                resp = conn.getresponse()
                data = resp.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise SsrfRejected("too-large")
                hdrs = {k.lower(): v for k, v in resp.getheaders()}
                status = resp.status
            finally:
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
