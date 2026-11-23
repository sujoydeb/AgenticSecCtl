"""Redaction for logs, errors and findings (TC-G5) and escaping of untrusted text."""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_KEY = re.compile(
    r"(authorization|cookie|passw(or)?d|passphrase|secret|token|api[-_]?key|private[-_]?key|credential|session)",
    re.I,
)
_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
]
_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]*:)[^\s/@]+(@)", re.I)


def _scrub(s: str) -> str:
    for p in _VALUE_PATTERNS:
        s = p.sub(REDACTED, s)
    return _USERINFO.sub(lambda m: m.group(1) + REDACTED + m.group(2), s)


def redact(value: Any) -> Any:
    """Return a redacted deep copy; the input is never mutated."""
    if isinstance(value, dict):
        return {k: (REDACTED if isinstance(k, str) and _KEY.search(k) else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _scrub(value)
    return value


def escape_untrusted(text: str, limit: int = 200) -> str:
    """Escape control, ANSI and quote characters and bound the length (FR-AUD-5)."""
    out: list[str] = []
    size = 0
    for ch in text:
        o = ord(ch)
        if ch in "\"\\":
            piece = "\\" + ch
        elif o < 0x20 or 0x7F <= o <= 0x9F or o in (0x2028, 0x2029):
            piece = f"\\u{o:04x}"
        else:
            piece = ch
        if size + len(piece) > limit:
            break
        out.append(piece)
        size += len(piece)
    return "".join(out)
