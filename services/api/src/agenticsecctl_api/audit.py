"""Database-backed audit chain writer, verifier and reader (WP-1.4 model, WP-1.6 storage; FR-AUD-1/2, CTL-13).

Runs as the ``audit_writer`` role, the only role allowed to insert into ``audit_events``. It moves events
from the outbox into the per-tenant hash chain: one transaction per batch, writers for a tenant serialised
by an advisory lock, and the database itself refuses a gap, a fork or a wrong previous hash (trigger
``audit_events_chain``). The hash is computed by ``agenticsecctl_common.auditchain`` so the verifier and the
writer cannot disagree. The chain is tamper-evident, not tamper-proof: a privileged actor who rewrites it
consistently is only caught by an external anchor (Phase 2).
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from agenticsecctl_common.auditchain import GENESIS_HASH, VerifyResult, compute_hash, verify_chain

from .db import Conn, Database

_OPTIONAL = ("subject_type", "subject_id", "decision", "policy_hash", "input_digest", "payload_digest", "redacted_excerpt")


def _stamp(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row_to_event(tenant: str, r: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the exact dict that was hashed (null columns were never part of the event)."""
    row: dict[str, Any] = {"event_id": r["event_id"], "occurred_at": _stamp(r["occurred_at"]), "event_type": r["event_type"],
                           "actor": r["actor"], "tenant_id": tenant, "seq": r["seq"]}
    for k in _OPTIONAL:
        if r[k] is not None:
            row[k] = r[k]
    row["prev_hash"], row["hash"] = bytes(r["prev_hash"]).hex(), bytes(r["hash"]).hex()
    return row


def drain(db: Database, tenant: str, *, batch: int = 500) -> int:
    """Chain up to ``batch`` pending outbox events of one tenant. Returns how many were written."""
    with db.transaction(tenant) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 7))", [tenant])
        pending = conn.execute("SELECT id, event FROM outbox WHERE state = 'pending' ORDER BY id LIMIT %s FOR UPDATE SKIP LOCKED", [batch]).fetchall()
        if not pending:
            return 0
        last = conn.execute("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev = (last["seq"], bytes(last["hash"]).hex()) if last else (0, GENESIS_HASH)
        for p in pending:
            ev = p["event"]
            seq += 1
            body = {k: v for k, v in ev.items() if k in ("event_id", "occurred_at", "event_type", "actor", *_OPTIONAL)}
            body.update(tenant_id=tenant, seq=seq)
            h = compute_hash(prev, body)
            conn.execute(
                "INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, subject_type, subject_id, decision, "
                "policy_hash, input_digest, payload_digest, redacted_excerpt, prev_hash, hash) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [tenant, seq, ev["event_id"], ev["occurred_at"], ev["event_type"], ev["actor"], ev.get("subject_type"), ev.get("subject_id"),
                 ev.get("decision"), ev.get("policy_hash"), ev.get("input_digest"), ev.get("payload_digest"), ev.get("redacted_excerpt"),
                 bytes.fromhex(prev), bytes.fromhex(h)])
            conn.execute("UPDATE outbox SET state = 'processed', processed_at = now() WHERE id = %s", [p["id"]])
            prev = h
        return len(pending)


def tenants_with_pending(db: Database, tenants: list[str]) -> list[str]:
    out = []
    for t in tenants:
        with db.transaction(t) as conn:
            if conn.execute("SELECT 1 FROM outbox WHERE state = 'pending' LIMIT 1").fetchone():
                out.append(t)
    return out


def rows(conn: Conn, tenant: str) -> list[dict[str, Any]]:
    return [_row_to_event(tenant, r) for r in conn.execute("SELECT * FROM audit_events ORDER BY seq")]


def verify(conn: Conn, tenant: str, expected_head: tuple[int, str] | None = None) -> VerifyResult:
    """Verify the tenant's whole chain as stored (POST /audit/verification). A failure is a finding for the caller to record."""
    return verify_chain(rows(conn, tenant), expected_head)
