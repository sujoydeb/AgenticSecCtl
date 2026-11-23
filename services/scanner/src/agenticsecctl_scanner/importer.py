"""Hardened tool importer (FR-SCAN-6, CTL-02, TC-Z2, AC-8).

Everything a hostile server controls is bounded before it is believed: wall-clock time (a deadline, not only per
read), response bytes, JSON nesting depth (checked on the bytes before parsing), node count, string length, tool
count, page count and event count. Redirects are never followed. Duplicate JSON keys, NaN and Infinity are refused,
because a parser that accepts them can read a different definition than the gateway hashes. Every connection goes
through the guarded client, so private and metadata addresses are refused at connect time. A failure is an
``ImportFailed`` with a stable reason code; nothing the server sent is echoed in it.

Request format (``tools/list`` over Streamable HTTP, revision 2026-07-28 has no initialize handshake, see
docs/mcp-compatibility.md): the protocol version goes in the ``MCP-Protocol-Version`` header and in ``params._meta``.
The exact ``_meta`` key names are an assumption [VERIFY] until the fixtures are run against a real SDK server.
"""
from __future__ import annotations

import json
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agenticsecctl_common.http import GuardedClient, SsrfRejected

PROTOCOL_VERSION = "2026-07-28"


class ImportFailed(Exception):
    def __init__(self, reason: str, retryable: bool = False):
        super().__init__(reason)
        self.reason, self.retryable = reason, retryable


@dataclass(frozen=True)
class ImportLimits:
    """Proposed values for PAR-O-01 (importer limits); to be confirmed by the security engineer."""
    total_timeout: float = 15.0      # whole import, all pages
    read_timeout: float = 5.0        # one socket operation
    max_bytes: int = 1_000_000       # one response
    max_depth: int = 20
    max_nodes: int = 100_000
    max_string_chars: int = 100_000
    max_tools: int = 500
    max_pages: int = 10
    max_events: int = 50             # server-sent events read from one response
    max_name_chars: int = 128
    max_cursor_chars: int = 512


def check_depth(raw: bytes, limit: int) -> None:
    """Reject nesting deeper than ``limit`` without recursion, before any JSON parser sees the bytes."""
    depth, in_str, esc = 0, False, False
    for b in raw:
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:
                esc = True
            elif b == 0x22:
                in_str = False
        elif b == 0x22:
            in_str = True
        elif b in (0x5B, 0x7B):
            depth += 1
            if depth > limit:
                raise ImportFailed("too-deep")
        elif b in (0x5D, 0x7D):
            depth -= 1


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ImportFailed("duplicate-key")
        d[k] = v
    return d


def _bad_constant(_: str) -> Any:
    raise ImportFailed("bad-number")


def _count(node: Any, limits: ImportLimits, budget: list[int]) -> None:
    """Iterative walk: counts nodes and checks strings and numbers."""
    stack = [node]
    while stack:
        n = stack.pop()
        budget[0] -= 1
        if budget[0] < 0:
            raise ImportFailed("too-many-nodes")
        if isinstance(n, str):
            if len(n) > limits.max_string_chars:
                raise ImportFailed("string-too-long")
        elif isinstance(n, float):
            if not math.isfinite(n):
                raise ImportFailed("bad-number")
        elif isinstance(n, dict):
            for k, v in n.items():
                budget[0] -= 1
                if len(k) > limits.max_string_chars:
                    raise ImportFailed("string-too-long")
                stack.append(v)
        elif isinstance(n, list):
            stack.extend(n)


def parse_json(raw: bytes, limits: ImportLimits) -> Any:
    if len(raw) > limits.max_bytes:
        raise ImportFailed("too-large")
    check_depth(raw, limits.max_depth)
    try:
        text = raw.decode("utf-8")  # strict: invalid UTF-8 is refused, not replaced
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_bad_constant)
    except ImportFailed:
        raise
    except (ValueError, RecursionError, MemoryError):
        raise ImportFailed("bad-json") from None
    _count(value, limits, [limits.max_nodes])
    return value


def _sse_payload(raw: bytes, limits: ImportLimits, request_id: int) -> Any:
    """The first complete message whose id matches the request; at most ``max_events`` events are looked at."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ImportFailed("bad-json") from None
    events = text.replace("\r\n", "\n").replace("\r", "\n").split("\n\n")
    for ev in events[: limits.max_events]:
        data = "\n".join(line[5:].lstrip(" ") for line in ev.split("\n") if line.startswith("data:"))
        if not data:
            continue
        msg = parse_json(data.encode("utf-8"), limits)
        if isinstance(msg, dict) and msg.get("id") == request_id and ("result" in msg or "error" in msg):
            return msg
    raise ImportFailed("no-response-event")


def parse_response(raw: bytes, content_type: str, limits: ImportLimits, request_id: int) -> dict[str, Any]:
    """Return the ``result`` object of a JSON-RPC response (JSON or event stream)."""
    ctype = content_type.split(";")[0].strip().lower()
    if ctype == "application/json":
        msg = parse_json(raw, limits)
    elif ctype == "text/event-stream":
        msg = _sse_payload(raw, limits, request_id)
    else:
        raise ImportFailed("content-type")
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or msg.get("id") != request_id or isinstance(msg.get("id"), bool):
        raise ImportFailed("bad-envelope")
    if ("result" in msg) == ("error" in msg):
        raise ImportFailed("bad-envelope")
    if "error" in msg:
        raise ImportFailed("server-error")  # the message is untrusted text and is not carried along
    if not isinstance(msg["result"], dict):
        raise ImportFailed("bad-envelope")
    return msg["result"]


def _check_tool(t: Any, limits: ImportLimits) -> None:
    if not isinstance(t, dict):
        raise ImportFailed("bad-tool")
    name = t.get("name")
    if not isinstance(name, str) or not 0 < len(name) <= limits.max_name_chars or not name.isprintable() or name != name.strip():
        raise ImportFailed("bad-tool-name")


def fetch_tool_definitions(client: GuardedClient, url: str, limits: ImportLimits = ImportLimits(), *, clock: Callable[[], float] | None = None) -> list[dict[str, Any]]:  # noqa: B008
    """Page through ``tools/list`` and return the tool objects exactly as the server sent them."""
    import time
    now = clock or time.monotonic
    deadline = now() + limits.total_timeout
    tools: list[dict[str, Any]] = []
    names: set[str] = set()
    cursors: set[str] = set()
    cursor: str | None = None
    for page in range(limits.max_pages):
        left = deadline - now()
        if left <= 0:
            raise ImportFailed("timeout", retryable=True)
        params: dict[str, Any] = {"_meta": {"protocolVersion": PROTOCOL_VERSION}}
        if cursor is not None:
            params["cursor"] = cursor
        body = json.dumps({"jsonrpc": "2.0", "id": page + 1, "method": "tools/list", "params": params}).encode()
        try:
            resp = client.request("POST", url, body=body, timeout=min(limits.read_timeout, left), total_timeout=left,
                                  max_bytes=limits.max_bytes, follow_redirects=False,
                                  headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                           "MCP-Protocol-Version": PROTOCOL_VERSION})
        except SsrfRejected as exc:
            raise ImportFailed(f"guard:{exc.reason}", retryable=exc.reason in ("timeout", "incomplete-body", "protocol-error")) from None
        except OSError:
            raise ImportFailed("connection-error", retryable=True) from None
        if 300 <= resp.status < 400:
            raise ImportFailed("redirect")
        if resp.status >= 500:
            raise ImportFailed("http-status", retryable=True)
        if resp.status != 200:
            raise ImportFailed("http-status")
        result = parse_response(resp.body, resp.headers.get("content-type", ""), limits, page + 1)
        listed = result.get("tools")
        if not isinstance(listed, list):
            raise ImportFailed("bad-envelope")
        for t in listed:
            _check_tool(t, limits)
            if t["name"] in names:
                raise ImportFailed("duplicate-tool-name")
            names.add(t["name"])
            tools.append(t)
            if len(tools) > limits.max_tools:
                raise ImportFailed("too-many-tools")
        nxt = result.get("nextCursor")
        if nxt is None:
            return tools
        if not isinstance(nxt, str) or not nxt or len(nxt) > limits.max_cursor_chars:
            raise ImportFailed("bad-cursor")
        if nxt in cursors:
            raise ImportFailed("cursor-loop")
        cursors.add(nxt)
        cursor = nxt
    raise ImportFailed("too-many-pages")
