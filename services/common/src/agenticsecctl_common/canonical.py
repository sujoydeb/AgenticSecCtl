"""RFC 8785 (JSON Canonicalization Scheme) and SHA-256 helpers.

Stdlib only. Numbers follow the ECMAScript Number-to-string rules; integers
outside the I-JSON safe range, NaN and infinities are rejected rather than
silently rounded, because a hash must never depend on a lossy conversion.
"""
from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any

MAX_SAFE_INT = 2**53 - 1

_SHORT = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if o in _SHORT:
            out.append(_SHORT[o])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        elif 0xD800 <= o <= 0xDFFF:
            raise ValueError("lone surrogate is not valid JSON text")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(v: int | float) -> str:
    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise ValueError("integer outside the I-JSON safe range")
        return str(v)
    if math.isnan(v) or math.isinf(v):
        raise ValueError("NaN and infinity are not allowed")
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    t = Decimal(repr(abs(v))).as_tuple()
    digits = "".join(map(str, t.digits)).rstrip("0") or "0"
    # value = 0.DIGITS * 10**n  (ECMAScript's k, n)
    if not isinstance(t.exponent, int):  # NaN and infinity were refused above; this keeps the type honest
        raise ValueError("not a finite number")
    n = len(t.digits) + t.exponent
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _encode(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, (int, float)):
        return _number(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_encode(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string(k) + ":" + _encode(x) for k, x in items) + "}"
    raise TypeError(f"type {type(v).__name__} is not JSON serialisable")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical form of ``value`` as UTF-8 bytes."""
    return _encode(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
