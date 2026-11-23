"""Tool-definition hash (IG-8, plan WP-1.2).

Hash input: canonical JSON of {"server_id", "tool"} where every string
(keys included) is first normalised to Unicode NFC. ``tool`` keeps the hashed
fields plus any unknown field (which is also reported). List-level metadata and
``_meta`` are excluded. Absent and null differ; array order is significant.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize, sha256_hex

HASHED_FIELDS = ("name", "title", "description", "icons", "inputSchema", "outputSchema", "annotations")
EXCLUDED_FIELDS = frozenset({"_meta", "ttlMs", "cacheScope", "resultType"})


@dataclass(frozen=True)
class ToolHash:
    digest: str
    unknown_fields: tuple[str, ...]


def _nfc(v: Any) -> Any:
    if isinstance(v, str):
        return unicodedata.normalize("NFC", v)
    if isinstance(v, dict):
        return {unicodedata.normalize("NFC", k): _nfc(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_nfc(x) for x in v]
    return v


def tool_definition_hash(server_id: str, tool: dict[str, Any]) -> ToolHash:
    kept = {k: x for k, x in tool.items() if k not in EXCLUDED_FIELDS}
    unknown = tuple(sorted(k for k in kept if k not in HASHED_FIELDS))
    doc = _nfc({"server_id": server_id, "tool": kept})
    return ToolHash(sha256_hex(canonicalize(doc)), unknown)
