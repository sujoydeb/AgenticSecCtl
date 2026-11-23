"""Text normalisation for the scanner (FR-SCAN-1, CTL-02).

Rules never match the raw string. They match a *view* that makes the usual evasions visible:

* invisible characters are located (offset, code point, kind) and removed from the visible text;
* Unicode tag characters (U+E0000 block) are decoded, because they can carry a whole instruction that no
  reviewer sees;
* text between a right-to-left override and its end is also read in reverse, as the model would see the
  characters in logical order while a reviewer sees them mirrored;
* compatibility forms (full-width letters) are folded and common Cyrillic and Greek look-alikes are mapped to
  Latin in a separate "skeleton", and words that mix scripts are reported;
* base64, hex and percent-encoded blobs are decoded (at most ``MAX_DECODE_DEPTH`` layers).

Everything is bounded: very long inputs are cut to a head and a tail window and flagged, so a large filler
cannot hide an instruction at the end and cannot make a regular expression run for long.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

MAX_CHARS = 50_000
MAX_DECODE_DEPTH = 3
MAX_BLOBS = 20

ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x2061, 0x2062, 0x2063, 0x2064})
BIDI_CONTROLS = frozenset(set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)))
BIDI_MARKS = frozenset({0x200E, 0x200F, 0x061C})  # harmless in genuine right-to-left text
_RLO, _RLI, _PDF, _PDI = 0x202E, 0x2067, 0x202C, 0x2069

# Look-alikes that survive NFKC. Deliberately small: unknown characters stay as they are (and mixed-script words
# are reported anyway); this is a detection aid, not a full confusables table.
CONFUSABLES = {
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y",
    "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ӏ": "l", "ο": "o", "α": "a", "ν": "v", "ρ": "p",
    "ι": "i", "κ": "k", "τ": "t", "υ": "u", "χ": "x", "ε": "e", "η": "n", "Ι": "I", "Ο": "O", "Α": "A", "Β": "B",
    "Ε": "E", "Ζ": "Z", "Η": "H", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Χ": "X", "А": "A", "В": "B",
    "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J",
}
_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){10,}(?![0-9A-Fa-f])")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){6,}")
_WS = re.compile(r"\s+")


@dataclass(frozen=True)
class Hidden:
    offset: int
    codepoint: int
    kind: str  # zero-width | bidi | tag | format


@dataclass(frozen=True)
class Blob:
    kind: str  # base64 | hex | percent
    encoded: str
    decoded: str


@dataclass
class Normalised:
    original: str
    text: str                      # NFC, invisible characters removed
    skeleton: str                  # lower-case, folded, look-alikes mapped, whitespace collapsed
    hidden: tuple[Hidden, ...] = ()
    hidden_tag_text: str = ""      # decoded Unicode tag characters
    reversed_segments: tuple[str, ...] = ()
    mixed_script_words: tuple[str, ...] = ()
    blobs: tuple[Blob, ...] = ()
    truncated: bool = False
    stats: dict[str, int] = field(default_factory=dict)


def _window(text: str, limit: int) -> tuple[str, bool]:
    """Head and tail of an over-long text, so filler in the middle cannot hide an instruction at either end."""
    if len(text) <= limit:
        return text, False
    half = limit // 2
    return text[:half] + " " + text[-half:], True


def _classify(cp: int) -> str | None:
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    if cp in ZERO_WIDTH:
        return "zero-width"
    if cp in BIDI_CONTROLS:
        return "bidi"
    if cp in BIDI_MARKS:
        return None
    if unicodedata.category(chr(cp)) == "Cf" or cp == 0xAD:
        return "format"
    return None


def _printable_ratio(b: bytes) -> float:
    return sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b) if b else 0.0


def _decode_text(b: bytes) -> str | None:
    if len(b) < 8 or _printable_ratio(b) < 0.9:
        return None
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


def find_blobs(text: str) -> tuple[Blob, ...]:
    out: list[Blob] = []
    for m in _B64.finditer(text):
        raw = m.group(0)
        if len(out) >= MAX_BLOBS:
            break
        try:
            dec = _decode_text(base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True))
        except (binascii.Error, ValueError):
            continue
        if dec:
            out.append(Blob("base64", raw, dec))
    for m in _HEX.finditer(text):
        if len(out) >= MAX_BLOBS:
            break
        dec = _decode_text(bytes.fromhex(m.group(0)))
        if dec:
            out.append(Blob("hex", m.group(0), dec))
    for m in _PCT.finditer(text):
        if len(out) >= MAX_BLOBS:
            break
        dec = urllib.parse.unquote(m.group(0))
        if _printable_ratio(dec.encode("utf-8", "replace")) > 0.9:
            out.append(Blob("percent", m.group(0), dec))
    return tuple(out)


def _mixed_words(text: str) -> tuple[str, ...]:
    out = []
    for w in re.findall(r"[^\W\d_]+", text):
        scripts = set()
        for ch in w:
            if ch.isalpha():
                n = unicodedata.name(ch, "")
                for s in _SCRIPTS:
                    if n.startswith(s):
                        scripts.add(s)
        if len(scripts) > 1:
            out.append(w)
        if len(out) >= 20:
            break
    return tuple(out)


def _reversed(text: str) -> tuple[str, ...]:
    segs: list[str] = []
    i, n = 0, len(text)
    while i < n and len(segs) < 20:
        if ord(text[i]) in (_RLO, _RLI):
            j = i + 1
            while j < n and ord(text[j]) not in (_PDF, _PDI):
                j += 1
            seg = "".join(c for c in text[i + 1:j] if _classify(ord(c)) is None)
            if seg.strip():
                segs.append(seg[::-1])
            i = j
        i += 1
    return tuple(segs)


def skeleton_of(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text)
    folded = "".join(CONFUSABLES.get(c, c) for c in folded)
    return _WS.sub(" ", folded.lower()).strip()


def normalise(raw: str, *, max_chars: int = MAX_CHARS) -> Normalised:
    text, cut = _window(raw, max_chars)
    hidden: list[Hidden] = []
    visible: list[str] = []
    tag_chars: list[str] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        kind = _classify(cp) if cp > 0x7F else None
        if kind is None:
            visible.append(ch)
            continue
        if len(hidden) < 500:
            hidden.append(Hidden(i, cp, kind))
        if kind == "tag" and 0xE0020 <= cp <= 0xE007E:
            tag_chars.append(chr(cp - 0xE0000))
        # zero-width, bidi and format characters are dropped from the visible text (not replaced by a space)
    clean = unicodedata.normalize("NFC", "".join(visible))
    return Normalised(
        original=raw, text=clean, skeleton=skeleton_of(clean), hidden=tuple(hidden),
        hidden_tag_text="".join(tag_chars), reversed_segments=_reversed(text),
        mixed_script_words=_mixed_words(clean), blobs=find_blobs(clean), truncated=cut,
        stats={"chars": len(raw), "hidden": len(hidden)},
    )
