"""Access-token validation (FR-AUTHN-1, CTL-04, TC-F2, TC-G2).

Only RS256 is accepted. The algorithm comes from this code, never from the
token: ``none``, HMAC and every other algorithm are refused before any key is
looked up. Headers that make a verifier fetch or trust a key supplied by the
token (``jku``, ``jwk``, ``x5u``, ``x5c``, ``crit``) are refused. Failure
reasons are stable codes and never echo token content.
"""
from __future__ import annotations

import base64
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .rsa import KeysUnavailable, RsaPublicKey, verify_rs256

MAX_TOKEN_BYTES = 8192
MAX_LIFETIME_SECONDS = 600  # PAR-F-03
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_FORBIDDEN_HEADERS = {"jku", "jwk", "x5u", "x5c", "crit"}


class AuthError(Exception):
    """Authentication failed. ``reason`` is a stable code safe to log and count."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class KeySource(Protocol):
    def get(self, kid: str) -> RsaPublicKey | None: ...


@dataclass(frozen=True)
class Claims:
    subject: str
    issuer: str
    audience: tuple[str, ...]
    client_id: str
    scopes: frozenset[str]
    issued_at: float
    expires_at: float
    raw: dict[str, Any]


def _b64(part: str) -> bytes:
    if not _B64.match(part):
        raise AuthError("malformed")
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except ValueError:
        raise AuthError("malformed") from None


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise AuthError("malformed") from None
    if not isinstance(obj, dict):
        raise AuthError("malformed")
    return obj


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


class TokenValidator:
    def __init__(self, *, issuer: str, audience: str, keys: KeySource,
                 max_lifetime: int = MAX_LIFETIME_SECONDS, leeway: int = 30,
                 required_scopes: tuple[str, ...] = (), clock: Callable[[], float] = time.time):
        if max_lifetime > MAX_LIFETIME_SECONDS or max_lifetime <= 0:
            raise ValueError("max_lifetime must be between 1 and 600 seconds")
        if not 0 <= leeway <= 60:
            raise ValueError("leeway must be between 0 and 60 seconds")
        self._iss, self._aud, self._keys = issuer, audience, keys
        self._max, self._leeway, self._scopes, self._clock = max_lifetime, leeway, frozenset(required_scopes), clock

    def validate(self, token: Any) -> Claims:
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
            raise AuthError("malformed")
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthError("malformed")
        header = _json_object(_b64(parts[0]))
        payload = _json_object(_b64(parts[1]))
        signature = _b64(parts[2]) if parts[2] else b""

        if header.get("alg") != "RS256":
            raise AuthError("alg")
        if _FORBIDDEN_HEADERS & header.keys():
            raise AuthError("header")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthError("header")

        try:
            key = self._keys.get(kid)
        except KeysUnavailable:
            raise AuthError("keys-unavailable") from None
        if key is None or not key.usable:
            raise AuthError("kid")
        if not verify_rs256(key, f"{parts[0]}.{parts[1]}".encode("ascii"), signature):
            raise AuthError("signature")
        return self._claims(payload)

    def _claims(self, p: dict[str, Any]) -> Claims:
        now = self._clock()
        if p.get("iss") != self._iss:
            raise AuthError("iss")
        aud = p.get("aud")
        auds = (aud,) if isinstance(aud, str) else tuple(aud) if isinstance(aud, list) else ()
        if not auds or not all(isinstance(a, str) for a in auds) or self._aud not in auds:
            raise AuthError("aud")
        exp, iat, nbf = _num(p.get("exp")), _num(p.get("iat")), p.get("nbf")
        if exp is None or now >= exp + self._leeway:
            raise AuthError("exp")
        if nbf is not None:
            nbf_value = _num(nbf)
            if nbf_value is None or nbf_value > now + self._leeway:
                raise AuthError("nbf")
        if iat is None or iat > now + self._leeway:
            raise AuthError("iat")
        if exp - iat > self._max:
            raise AuthError("lifetime")
        sub = p.get("sub")
        if not isinstance(sub, str) or not sub:
            raise AuthError("sub")
        client = p.get("azp") or p.get("client_id")
        if not isinstance(client, str) or not client:
            raise AuthError("client")
        scope = p.get("scope")
        scopes = frozenset(scope.split()) if isinstance(scope, str) else frozenset()
        if not self._scopes <= scopes:
            raise AuthError("scope")
        return Claims(sub, self._iss, auds, client, scopes, iat, exp, p)
