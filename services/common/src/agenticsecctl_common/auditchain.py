"""Tamper-evident audit chain (FR-AUD-1, FR-AUD-2, CTL-13).

``hash_n = SHA-256(hash_{n-1} || canonical(event_n))`` per tenant, starting from a
fixed genesis value. The chain is tamper-evident, not tamper-proof: a privileged
actor who rewrites the whole chain consistently is only caught by an external
anchor (Phase 2, TC-Z22). ``expected_head`` lets a caller who holds the last
anchored (seq, hash) detect tail truncation.

``ChainWriter`` is the in-memory reference writer used by tests and as the model
for the database-backed writer in the API (WP-1.5/1.6): writers are serialised
per tenant, sequence numbers are gap-free, and a repeated ``event_id`` is
ignored so a retried batch cannot duplicate events.
"""
from __future__ import annotations

import datetime as _dt
import threading
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize, sha256_hex
from .contracts import EVENT_TYPES
from .redact import escape_untrusted, redact

GENESIS_HASH = "0" * 64
EXCERPT_LIMIT = 256

REQUIRED = ("event_id", "occurred_at", "event_type", "actor")
OPTIONAL = ("subject_type", "subject_id", "decision", "policy_hash", "input_digest",
            "payload_digest", "redacted_excerpt")
_CHAIN_FIELDS = ("hash", "prev_hash", "seq", "tenant_id")


class EventError(ValueError):
    """The event is malformed; nothing was written."""


def compute_hash(prev_hash: str, body: dict[str, Any]) -> str:
    """``body`` is the row without ``hash`` and ``prev_hash``."""
    return sha256_hex(bytes.fromhex(prev_hash) + canonicalize(body))


def _body(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in ("hash", "prev_hash")}


def validate_event(event: dict[str, Any]) -> None:
    for k in event:
        if k in _CHAIN_FIELDS:
            raise EventError(f"field {k!r} is assigned by the chain writer")
        if k not in REQUIRED and k not in OPTIONAL:
            raise EventError(f"unknown field {k!r}")
    for k in REQUIRED:
        if not isinstance(event.get(k), str) or not event[k]:
            raise EventError(f"field {k!r} is required")
    if event["event_type"] not in EVENT_TYPES:
        raise EventError("event_type is not in the vocabulary")
    for k in OPTIONAL:
        if k in event and not isinstance(event[k], str):
            raise EventError(f"field {k!r} must be a string")


class ChainWriter:
    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._rows: dict[str, list[dict[str, Any]]] = {}
        self._ids: dict[str, dict[str, tuple[str, dict[str, Any]]]] = {}

    def _lock(self, tenant: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(tenant, threading.Lock())

    def rows(self, tenant: str) -> list[dict[str, Any]]:
        with self._lock(tenant):
            return [dict(r) for r in self._rows.get(tenant, [])]

    def append(self, tenant: str, event: dict[str, Any]) -> dict[str, Any]:
        if not tenant:
            raise EventError("tenant is required")
        validate_event(event)
        digest = sha256_hex(canonicalize(event))
        with self._lock(tenant):
            seen = self._ids.setdefault(tenant, {})
            prior = seen.get(event["event_id"])
            if prior:
                if prior[0] != digest:
                    raise EventError("event_id was already used with different content")
                return dict(prior[1])
            rows = self._rows.setdefault(tenant, [])
            row: dict[str, Any] = dict(event)
            if "redacted_excerpt" in row:
                row["redacted_excerpt"] = escape_untrusted(redact(row["redacted_excerpt"]), EXCERPT_LIMIT)
            row["tenant_id"] = tenant
            row["seq"] = len(rows) + 1
            prev = rows[-1]["hash"] if rows else GENESIS_HASH
            row["prev_hash"] = prev
            row["hash"] = compute_hash(prev, _body(row))
            rows.append(row)
            seen[event["event_id"]] = (digest, row)
            return dict(row)

    def append_batch(self, tenant: str, events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        events = list(events)
        for e in events:  # validate all first so a bad batch writes nothing
            validate_event(e)
        return [self.append(tenant, e) for e in events]


@dataclass
class VerifyResult:
    ok: bool
    checked: int = 0
    first_bad_seq: int | None = None
    kind: str | None = None  # modified | deleted | reordered | tenant
    detail: str = ""
    tenant_id: str = ""

    def as_event(self) -> dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "occurred_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": "audit.verify.failed", "actor": "system:verifier",
            "subject_type": "audit_chain", "subject_id": str(self.first_bad_seq),
            "decision": "fail", "redacted_excerpt": f"{self.kind}: {self.detail}",
        }


def _fail(n: int, seq: int | None, kind: str, detail: str, tenant: str) -> VerifyResult:
    return VerifyResult(False, n, seq, kind, detail, tenant)


def verify_chain(rows: list[dict[str, Any]], expected_head: tuple[int, str] | None = None) -> VerifyResult:
    """Verify rows of one tenant in storage order and report the first bad sequence."""
    tenant = rows[0].get("tenant_id", "") if rows else ""
    later = {r.get("seq") for r in rows}
    running, expected = GENESIS_HASH, 1
    for i, r in enumerate(rows):
        seq = r.get("seq")
        if r.get("tenant_id") != tenant:
            return _fail(i, seq, "tenant", "rows of more than one tenant", tenant)
        if not isinstance(seq, int):
            return _fail(i, expected, "modified", "missing sequence", tenant)
        if seq < expected:
            return _fail(i, seq, "reordered", f"sequence {seq} appears again or out of order", tenant)
        if seq > expected:
            if expected in later:
                return _fail(i, expected, "reordered", f"sequence {expected} is out of place", tenant)
            return _fail(i, expected, "deleted", f"sequence {expected} is missing", tenant)
        if r.get("prev_hash") != running:
            return _fail(i, seq, "modified", "link to previous row broken", tenant)
        try:
            ok = compute_hash(running, _body(r)) == r.get("hash")
        except (ValueError, TypeError):
            ok = False
        if not ok:
            return _fail(i, seq, "modified", "row hash does not match its content", tenant)
        running, expected = r["hash"], seq + 1
    if expected_head is not None:
        hseq, hhash = expected_head
        if expected - 1 < hseq:
            return _fail(len(rows), expected, "deleted", f"rows after {expected - 1} are missing", tenant)
        if expected - 1 == hseq and running != hhash:
            return _fail(len(rows), hseq, "modified", "head hash differs from the anchor", tenant)
    return VerifyResult(True, len(rows), tenant_id=tenant)
