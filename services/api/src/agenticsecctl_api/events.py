"""Audit events through the outbox (data-model Section 1, rule 4): the event is inserted in the same
transaction as the change it describes, so the registry and the audit trail cannot diverge. The audit
writer (audit.py) turns outbox rows into the hash chain."""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

from agenticsecctl_common.auditchain import validate_event
from agenticsecctl_common.redact import escape_untrusted, redact

from .db import Conn


def now_text() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def emit(conn: Conn, tenant: str, event_type: str, actor: str, *, subject_type: str | None = None,
         subject_id: str | None = None, decision: str | None = None, excerpt: str | None = None) -> str:
    event: dict[str, Any] = {"event_id": str(uuid.uuid4()), "occurred_at": now_text(), "event_type": event_type, "actor": actor}
    for k, v in (("subject_type", subject_type), ("subject_id", subject_id), ("decision", decision)):
        if v is not None:
            event[k] = str(v)
    if excerpt:
        event["redacted_excerpt"] = escape_untrusted(redact(excerpt), 200)
    validate_event(event)
    conn.execute("INSERT INTO outbox (tenant_id, event) VALUES (%s, %s)", [tenant, json.dumps(event)])
    return str(event["event_id"])
