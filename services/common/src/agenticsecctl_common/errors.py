"""Error catalogue and builders (docs/cross-cutting-design.md Section 5).

Fixed text only: nothing untrusted is ever echoed. An unknown code maps to a
generic 500, never to a pass.
"""
from __future__ import annotations

from typing import Any

# code -> (HTTP status, title)
CATALOGUE: dict[str, tuple[int, str]] = {
    "invalid-request": (400, "Invalid request"),
    "unauthenticated": (401, "Authentication required"),
    "forbidden": (403, "Not permitted"),
    "separation-of-duties": (403, "Separation of duties"),
    "not-found": (404, "Not found"),
    "conflict": (409, "Conflict"),
    "ssrf-rejected": (422, "Address rejected"),
    "rate-limited": (429, "Rate limited"),
    "not-ready": (503, "Not ready"),
    "tool-unavailable": (404, "Tool unavailable"),
    "not-permitted": (403, "Not permitted"),
    "limit-reached": (429, "Limit reached"),
    "approval-required": (403, "Approval required"),
    "unsupported-version": (400, "Unsupported version"),
    "internal": (500, "Internal error"),
}
_TYPE_BASE = "urn:agenticsecctl:error:"


def problem_details(code: str, *, correlation_id: str) -> dict[str, Any]:
    """RFC 9457 problem details for the management API."""
    if code not in CATALOGUE:
        code = "internal"
    status, title = CATALOGUE[code]
    return {"type": _TYPE_BASE + code, "title": title, "status": status,
            "detail": title, "correlation_id": correlation_id}


def mcp_error(code: str, *, correlation_id: str, detail: str | None = None) -> dict[str, Any]:
    """JSON-RPC error object for agents. ``detail`` is accepted and deliberately ignored."""
    del detail
    if code not in CATALOGUE:
        code = "internal"
    return {"code": -32000, "message": CATALOGUE[code][1],
            "data": {"error": code, "correlation_id": correlation_id}}
