"""Key-set cache for the identity provider (CTL-04, IG-4).

Fail closed: when the key set cannot be fetched and the cached copy is older
than its TTL, ``get`` raises ``KeysUnavailable`` and the caller denies. An
unknown ``kid`` triggers at most one refresh per ``min_refresh_interval``, so
a flood of forged key IDs cannot be turned into a flood of requests to the
identity provider. All fetches go through the guarded client.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from ..http import GuardedClient
from .rsa import KeysUnavailable, RsaPublicKey

Fetch = Callable[[str], bytes]
MIN_KEY_BITS = 2048
MAX_KEYS = 20


def guarded_fetcher(client: GuardedClient, *, timeout: float = 5.0, max_bytes: int = 200_000) -> Fetch:
    def fetch(url: str) -> bytes:
        r = client.request("GET", url, timeout=timeout, max_bytes=max_bytes)
        if r.status != 200:
            raise OSError("identity provider returned an error status")
        return r.body
    return fetch


def _int(v: Any) -> int | None:
    if not isinstance(v, str):
        return None
    try:
        return int.from_bytes(base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)), "big")
    except ValueError:
        return None


def _parse_keys(doc: Any, min_bits: int) -> dict[str, RsaPublicKey]:
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list) or not doc["keys"]:
        raise KeysUnavailable("key set has no keys")
    out: dict[str, RsaPublicKey] = {}
    seen: set[str] = set()
    for jwk in doc["keys"][:MAX_KEYS]:
        if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
            continue
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        if kid in seen:
            raise KeysUnavailable("duplicate key id")
        seen.add(kid)
        if jwk.get("use") not in (None, "sig") or jwk.get("alg") not in (None, "RS256"):
            continue
        n, e = _int(jwk.get("n")), _int(jwk.get("e"))
        if n is None or e is None:
            continue
        key = RsaPublicKey(n, e, kid)
        if key.usable and key.bits >= min_bits:
            out[kid] = key
    return out


class JwksCache:
    def __init__(self, jwks_url: str, fetch: Fetch, *, ttl: int = 300, min_refresh_interval: int = 30,
                 min_bits: int = MIN_KEY_BITS, allow_http: bool = False,
                 clock: Callable[[], float] = time.time, discovery: tuple[str, str] | None = None):
        self._url, self._fetch, self._ttl, self._gap = jwks_url, fetch, ttl, min_refresh_interval
        self._min_bits, self._allow_http, self._clock, self._disc = min_bits, allow_http, clock, discovery
        self._keys: dict[str, RsaPublicKey] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = threading.Lock()

    @classmethod
    def from_discovery(cls, issuer: str, fetch: Fetch, *, allow_http: bool = False, **kw: Any) -> JwksCache:
        c = cls("", fetch, allow_http=allow_http, discovery=(issuer, issuer.rstrip("/") + "/.well-known/openid-configuration"), **kw)
        return c

    def _scheme_ok(self, url: str) -> bool:
        s = urlsplit(url)
        return bool(s.hostname) and (s.scheme == "https" or (s.scheme == "http" and self._allow_http))

    def _resolve_url(self) -> str:
        if self._url:
            return self._url
        issuer, disc_url = self._disc  # type: ignore[misc]
        if not self._scheme_ok(disc_url):
            raise KeysUnavailable("discovery URL scheme is not allowed")
        try:
            doc = json.loads(self._fetch(disc_url))
        except (OSError, ValueError, Exception) as exc:  # noqa: BLE001 - any failure is a denial
            raise KeysUnavailable("discovery failed") from exc
        if not isinstance(doc, dict) or doc.get("issuer") != issuer:
            raise KeysUnavailable("discovery issuer does not match")
        uri = doc.get("jwks_uri")
        if not isinstance(uri, str) or not self._scheme_ok(uri):
            raise KeysUnavailable("jwks_uri is not allowed")
        return uri

    def _refresh(self, now: float) -> None:
        self._last_attempt = now
        url = self._resolve_url()
        try:
            doc = json.loads(self._fetch(url))
        except KeysUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure is a denial
            raise KeysUnavailable("key set fetch failed") from exc
        keys = _parse_keys(doc, self._min_bits)
        self._keys, self._fetched_at = keys, now

    def get(self, kid: str) -> RsaPublicKey | None:
        with self._lock:
            now = self._clock()
            fresh = self._fetched_at is not None and now - self._fetched_at < self._ttl
            if fresh and kid in self._keys:
                return self._keys[kid]
            can_try = self._last_attempt is None or now - self._last_attempt >= self._gap
            if fresh and not can_try:
                return None  # unknown kid inside the throttle window
            if not fresh or can_try:
                try:
                    self._refresh(now)
                except KeysUnavailable:
                    if not fresh:
                        self._keys, self._fetched_at = {}, None
                        raise
                    return None
            return self._keys.get(kid)
