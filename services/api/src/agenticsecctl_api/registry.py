"""Registry, approvals and separation of duties (WP-1.6).

Every function takes an open connection whose transaction already carries the tenant (``db.Database``),
so row-level security applies to every statement. Each state change inserts its audit event into the
outbox in the same transaction. Separation of duties is checked here and again by database constraints
(``approvals_sod``, ``permissions_sod``, the override triggers); the UI only hides buttons.

Rules implemented from the design: a tool definition is stored as canonical JSON plus SHA-256 and is
approved into an immutable version; a changed definition quarantines the tool until a new version is
approved; the action class is set by the approver, never taken from annotations; Critical findings block
approval unless an override has two distinct approvers (SoD-2); a server URL passes the SSRF guard before
it is stored; registry items default to the Confidential classification.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from psycopg import errors as pgerr

from agenticsecctl_common.canonical import canonicalize
from agenticsecctl_common.http import Guard, SsrfRejected, validate_url
from agenticsecctl_common.tooldef import tool_definition_hash

from .db import Conn
from .errors import Conflict, Invalid, NotFound, SeparationOfDuties, SsrfRefused
from .events import emit

ACTION_CLASSES = ("read", "write", "execute", "delete")
DEFAULT_LEVELS = (("Public", 0), ("Internal", 1), ("Confidential", 2), ("Restricted", 3))
MAX_OVERRIDE_DAYS = 90
RULESET = "registry-checks-1"


@dataclass(frozen=True)
class Actor:
    """Who a change is attributed to. ``user_id`` is the person recorded as requester (so separation of duties
    still applies); ``via`` names a service acting for them, which is what the audit event shows."""
    user_id: str
    tenant: str
    via: str | None = None

    @property
    def label(self) -> str:
        return f"service:{self.via}" if self.via else f"user:{self.user_id}"


def _j(v: Any) -> Any:
    """Make a row JSON-friendly (UUIDs, bytes, datetimes become text)."""
    if isinstance(v, dict):
        return {k: _j(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_j(x) for x in v]
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, (bytes, memoryview)):
        return bytes(v).hex()
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    return v


def _row(row: Any) -> dict[str, Any]:
    out: dict[str, Any] = _j(row)
    return out


def scalar(conn: Conn, sql: str, params: list[Any], key: str) -> Any:
    """One value from an aggregate query, which always returns a row; an absent row is an internal error, not a default."""
    row = conn.execute(sql, params).fetchone()  # type: ignore[call-overload,unused-ignore]
    if row is None:
        raise RuntimeError("aggregate query returned no row")
    return row[key]


def _text(value: Any, field: str, *, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise Invalid(f"{field} must be a non-empty string of at most {maximum} characters")
    return value.strip()


def _one(conn: Conn, sql: str, params: list[Any], what: str = "object") -> dict[str, Any]:
    row = conn.execute(sql, params).fetchone()
    if row is None:
        raise NotFound(what)  # other tenants' rows are invisible, so they are "not found" too
    return row


def _uuid(value: Any, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        raise Invalid(f"{field} must be a UUID") from None


def ensure_levels(conn: Conn, tenant: str) -> str:
    """Create the default classification levels if missing; return the id of Confidential (FR-DATA-1/2)."""
    for name, rank in DEFAULT_LEVELS:
        conn.execute("INSERT INTO classification_levels (tenant_id, name, rank) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                     [tenant, name, rank])
    return str(_one(conn, "SELECT id FROM classification_levels WHERE tenant_id = %s AND name = 'Confidential'", [tenant])["id"])


# ------------------------------------------------------------------ agents and servers

def register_agent(conn: Conn, actor: Actor, *, name: Any, identity_ref: Any, environment: Any = "dev",
                   criticality: Any = "medium") -> dict[str, Any]:
    name, identity_ref, environment = _text(name, "name"), _text(identity_ref, "identity_ref"), _text(environment, "environment", maximum=40)
    try:
        agent = conn.execute(
            "INSERT INTO agents (tenant_id, name, owner_user_id, environment, criticality, identity_ref, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
            [actor.tenant, name, actor.user_id, environment, criticality, identity_ref, actor.user_id]).fetchone()
    except pgerr.UniqueViolation:
        raise Conflict("agent name or identity already registered") from None
    except pgerr.CheckViolation:
        raise Invalid("criticality is not valid") from None
    if agent is None:
        raise RuntimeError("INSERT returned no row")
    ap = _one(conn, "INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by) VALUES (%s, 'agent', %s, %s) RETURNING id",
              [actor.tenant, agent["id"], actor.user_id])
    emit(conn, actor.tenant, "approval.requested", actor.label, subject_type="agent", subject_id=agent["id"])
    return {**_j(agent), "approval_id": str(ap["id"])}


def register_server(conn: Conn, actor: Actor, *, namespace: Any, url: Any, guard: Guard,
                    environment: Any = "dev", criticality: Any = "medium") -> dict[str, Any]:
    namespace, url = _text(namespace, "namespace", maximum=60), _text(url, "url", maximum=2000)
    try:
        validate_url(url, guard)  # FR-SSRF-1: before anything is stored
    except SsrfRejected as exc:
        raise SsrfRefused(exc.reason) from None
    level = ensure_levels(conn, actor.tenant)
    try:
        server = conn.execute(
            "INSERT INTO mcp_servers (tenant_id, namespace, url, owner_user_id, environment, criticality, classification_level_id, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING *",
            [actor.tenant, namespace, url, actor.user_id, _text(environment, "environment", maximum=40), criticality, level, actor.user_id]).fetchone()
    except pgerr.UniqueViolation:
        raise Conflict("namespace already registered") from None
    except pgerr.CheckViolation:
        raise Invalid("namespace or criticality is not valid") from None
    if server is None:
        raise RuntimeError("INSERT returned no row")
    emit(conn, actor.tenant, "server.registered", actor.label, subject_type="server", subject_id=server["id"])
    return _row(server)


def enqueue_import(conn: Conn, actor: Actor, server_id: str) -> dict[str, Any]:
    server = _one(conn, "SELECT id FROM mcp_servers WHERE id = %s", [_uuid(server_id, "server id")], "server")
    job = conn.execute("INSERT INTO scan_jobs (tenant_id, server_id, kind) VALUES (%s, %s, 'import') RETURNING *",
                       [actor.tenant, server["id"]]).fetchone()
    return _row(job)


# ------------------------------------------------------------------ tool definitions

def _registry_scan(conn: Conn, tenant: str, server_id: Any) -> Any:
    rs = conn.execute("SELECT id FROM rule_sets WHERE version = %s", [RULESET]).fetchone()
    if rs is None:
        rs = conn.execute("INSERT INTO rule_sets (tenant_id, version, content_hash) VALUES (%s, %s, %s) RETURNING id",
                          [tenant, RULESET, hashlib.sha256(RULESET.encode()).digest()]).fetchone()
    if rs is None:
        raise RuntimeError("INSERT returned no row")
    scan = conn.execute("INSERT INTO scans (tenant_id, server_id, rule_set_id, status, finished_at) VALUES (%s, %s, %s, 'completed', now()) RETURNING id",
                        [tenant, server_id, rs["id"]]).fetchone()
    if scan is None:
        raise RuntimeError("INSERT returned no row")
    return scan["id"]


def record_finding(conn: Conn, actor: Actor, *, tool_id: Any, scan_id: Any, rule_id: str, severity: str,
                   evidence: str | None = None, location: str | None = None) -> dict[str, Any]:
    try:
        row = conn.execute(
            "INSERT INTO findings (tenant_id, scan_id, tool_id, rule_id, severity, location, evidence_excerpt) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *",
            [actor.tenant, scan_id, tool_id, _text(rule_id, "rule_id", maximum=80), severity, location,
             (evidence or None) and evidence[:512]]).fetchone()
    except pgerr.CheckViolation:
        raise Invalid("severity is not valid") from None
    if row is None:
        raise RuntimeError("INSERT returned no row")
    emit(conn, actor.tenant, "finding.created", actor.label, subject_type="tool", subject_id=tool_id, excerpt=f"{severity} {rule_id}")
    return _row(row)


def submit_definitions(conn: Conn, actor: Actor, server_id: str, tools: Any) -> list[dict[str, Any]]:
    """Register tool definitions as returned by a server; every new or changed one needs approval."""
    if not isinstance(tools, list) or not tools or len(tools) > 500:
        raise Invalid("tools must be a list of 1 to 500 tool objects")
    server = _one(conn, "SELECT id, namespace FROM mcp_servers WHERE id = %s", [_uuid(server_id, "server id")], "server")
    out: list[dict[str, Any]] = []
    scan_id: Any = None
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise Invalid("every tool needs a name")
        name = tool["name"]
        try:
            canonical = json.loads(canonicalize(tool))  # also rejects NaN, huge integers and lone surrogates
        except (ValueError, TypeError):
            raise Invalid("tool definition is not canonicalisable JSON") from None
        h = tool_definition_hash(str(server["id"]), tool)
        digest = bytes.fromhex(h.digest)
        existing = conn.execute("SELECT * FROM tools WHERE server_id = %s AND name = %s FOR UPDATE", [server["id"], name]).fetchone()
        state, approval_id = "unchanged", None
        if existing is None:
            created = conn.execute("INSERT INTO tools (tenant_id, server_id, name, action_class, classification_level_id) "
                                   "SELECT %s, %s, %s, 'execute', id FROM classification_levels WHERE tenant_id = %s AND name = 'Confidential' RETURNING *",
                                   [actor.tenant, server["id"], name, actor.tenant]).fetchone()
            if created is None:  # no levels yet for this tenant
                ensure_levels(conn, actor.tenant)
                created = conn.execute("INSERT INTO tools (tenant_id, server_id, name, action_class, classification_level_id) "
                                       "SELECT %s, %s, %s, 'execute', id FROM classification_levels WHERE tenant_id = %s AND name = 'Confidential' RETURNING *",
                                       [actor.tenant, server["id"], name, actor.tenant]).fetchone()
            if created is None:
                raise RuntimeError("INSERT returned no row")
            existing, state = created, "new"
        else:
            cur = None
            if existing["current_version_id"]:
                cur = conn.execute("SELECT sha256 FROM tool_versions WHERE id = %s", [existing["current_version_id"]]).fetchone()
            pending = conn.execute("SELECT id, proposed_sha256 FROM approvals WHERE subject_type = 'tool' AND subject_id = %s AND status = 'pending'",
                                   [existing["id"]]).fetchone()
            if cur is not None and bytes(cur["sha256"]) == digest:
                state = "unchanged"
            elif pending is not None and bytes(pending["proposed_sha256"]) == digest:
                state, approval_id = "unchanged", str(pending["id"])
            else:
                state = "changed" if cur is not None else "resubmitted"
                if pending is not None:  # superseded by the newer definition
                    conn.execute("UPDATE approvals SET status = 'expired' WHERE id = %s", [pending["id"]])
                if cur is not None and existing["status"] == "approved":  # any change quarantines (FR-DRIFT-3)
                    conn.execute("UPDATE tools SET status = 'quarantined' WHERE id = %s", [existing["id"]])
                    emit(conn, actor.tenant, "tool.quarantined", actor.label, subject_type="tool", subject_id=existing["id"], excerpt="definition changed")
                elif existing["status"] == "rejected":
                    conn.execute("UPDATE tools SET status = 'pending' WHERE id = %s", [existing["id"]])
        if state in ("new", "changed", "resubmitted"):
            ap = _one(conn, "INSERT INTO approvals (tenant_id, subject_type, subject_id, requested_by, proposed_definition, proposed_sha256) "
                            "VALUES (%s, 'tool', %s, %s, %s, %s) RETURNING id",
                      [actor.tenant, existing["id"], actor.user_id, json.dumps(canonical), digest])
            approval_id = str(ap["id"])
            emit(conn, actor.tenant, "approval.requested", actor.label, subject_type="tool", subject_id=existing["id"])
            dup = state == "new" and _duplicate_name(conn, existing)
            if scan_id is None and (h.unknown_fields or dup):
                scan_id = _registry_scan(conn, actor.tenant, server["id"])
            if h.unknown_fields:
                record_finding(conn, actor, tool_id=existing["id"], scan_id=scan_id, rule_id="R-UNKNOWN-FIELD", severity="medium",
                               evidence="unknown fields: " + ", ".join(h.unknown_fields)[:200])
            if dup:  # shadowing risk (threat C)
                record_finding(conn, actor, tool_id=existing["id"], scan_id=scan_id, rule_id="R-DUP-NAME", severity="high",
                               evidence="the same tool name is exposed by another server")
        out.append({"tool_id": str(existing["id"]), "name": name, "qualified_name": f"{server['namespace']}__{name}",
                    "state": state, "approval_id": approval_id, "sha256": h.digest, "unknown_fields": list(h.unknown_fields)})
    return out


def _duplicate_name(conn: Conn, tool: dict[str, Any]) -> bool:
    return conn.execute("SELECT 1 FROM tools WHERE name = %s AND server_id <> %s LIMIT 1", [tool["name"], tool["server_id"]]).fetchone() is not None


def quarantine_tool(conn: Conn, actor: Actor, tool_id: str, reason: Any) -> dict[str, Any]:
    reason = _text(reason, "reason", maximum=300)
    tool = _one(conn, "SELECT * FROM tools WHERE id = %s FOR UPDATE", [_uuid(tool_id, "tool id")], "tool")
    if tool["status"] in ("approved", "pending"):
        conn.execute("UPDATE tools SET status = 'quarantined' WHERE id = %s", [tool["id"]])
        emit(conn, actor.tenant, "tool.quarantined", actor.label, subject_type="tool", subject_id=tool["id"], excerpt=reason)
    elif tool["status"] != "quarantined":
        raise Conflict("tool is not in a state that can be quarantined")
    return _row(_one(conn, "SELECT * FROM tools WHERE id = %s", [tool["id"]]))


# ------------------------------------------------------------------ approvals

def _blocking_findings(conn: Conn, tenant: str, tool_id: Any) -> list[Any]:
    return [r["id"] for r in conn.execute(
        "SELECT f.id FROM findings f WHERE f.tenant_id = %s AND f.tool_id = %s AND f.severity = 'critical' AND f.status = 'open' "
        "AND NOT EXISTS (SELECT 1 FROM overrides o WHERE o.tenant_id = f.tenant_id AND o.finding_id = f.id "
        "AND o.effective_at IS NOT NULL AND o.expires_at > now())", [tenant, tool_id])]


def decide_approval(conn: Conn, actor: Actor, approval_id: str, *, decision: Any, action_class: Any = None,
                    reason: Any = None, key: Any = None) -> dict[str, Any]:
    if decision not in ("approve", "reject"):
        raise Invalid("decision must be approve or reject")
    key = _text(key, "idempotency key", maximum=100)
    ap = _one(conn, "SELECT * FROM approvals WHERE id = %s FOR UPDATE", [_uuid(approval_id, "approval id")], "approval")
    if ap["status"] != "pending":
        if ap["decision_key"] == key and str(ap["decided_by"]) == actor.user_id:
            return _row(ap)  # replay of the same decision
        raise Conflict("approval was already decided or has expired")
    if str(ap["requested_by"]) == actor.user_id:
        raise SeparationOfDuties("requester cannot decide their own request")  # SoD-1
    now = dt.datetime.now(dt.UTC)
    approve = decision == "approve"
    note = _text(reason, "reason", maximum=300) if reason else None
    if ap["subject_type"] == "agent":
        agent = _one(conn, "SELECT * FROM agents WHERE id = %s FOR UPDATE", [ap["subject_id"]], "agent")
        if str(agent["owner_user_id"]) == actor.user_id:
            raise SeparationOfDuties("an agent owner cannot approve their own agent")
        if agent["status"] != "pending":
            raise Conflict("agent is not pending")
        if approve:
            conn.execute("UPDATE agents SET status = 'active', approved_by = %s WHERE id = %s", [actor.user_id, agent["id"]])
        else:
            conn.execute("UPDATE agents SET status = 'retired' WHERE id = %s", [agent["id"]])
    elif ap["subject_type"] == "tool":
        tool = _one(conn, "SELECT * FROM tools WHERE id = %s FOR UPDATE", [ap["subject_id"]], "tool")
        if tool["status"] not in ("pending", "quarantined"):
            raise Conflict("tool is not waiting for approval")
        if approve:
            if action_class not in ACTION_CLASSES:
                raise Invalid("approval needs an action class: read, write, execute or delete")
            blocking = _blocking_findings(conn, actor.tenant, tool["id"])
            if blocking:
                raise Conflict("critical findings block approval; an override with two distinct approvers is required")
            n = scalar(conn, "SELECT coalesce(max(version_no), 0) + 1 AS n FROM tool_versions WHERE tool_id = %s", [tool["id"]], "n")
            try:
                ver = _one(conn, "INSERT INTO tool_versions (tenant_id, tool_id, version_no, canonical_json, sha256, approved_by) "
                                 "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                           [actor.tenant, tool["id"], n, json.dumps(ap["proposed_definition"]), ap["proposed_sha256"], actor.user_id])
            except pgerr.UniqueViolation:
                raise Conflict("this exact definition is already an approved version") from None
            conn.execute("UPDATE tools SET status = 'approved', current_version_id = %s, action_class = %s WHERE id = %s",
                         [ver["id"], action_class, tool["id"]])
            conn.execute("UPDATE findings SET tool_version_id = %s WHERE tool_id = %s AND tool_version_id IS NULL", [ver["id"], tool["id"]])
        else:
            conn.execute("UPDATE tools SET status = CASE WHEN current_version_id IS NULL THEN 'rejected' ELSE status END WHERE id = %s", [tool["id"]])
    else:
        raise Invalid("this approval type is not handled in Phase 1")
    row = _one(conn, "UPDATE approvals SET status = %s, decided_by = %s, decided_at = %s, decision_key = %s, decision_reason = %s, "
                     "decided_action_class = %s WHERE id = %s RETURNING *",
               ["approved" if approve else "rejected", actor.user_id, now, key, note, action_class if approve and ap["subject_type"] == "tool" else None, ap["id"]])
    emit(conn, actor.tenant, "approval.granted" if approve else "approval.denied", actor.label, subject_type=ap["subject_type"], subject_id=ap["subject_id"], excerpt=note)
    if ap["subject_type"] == "tool":
        emit(conn, actor.tenant, "tool.approved" if approve else "tool.rejected", actor.label, subject_type="tool", subject_id=ap["subject_id"])
    return _row(row)


def request_override(conn: Conn, actor: Actor, approval_id: str, finding_id: str, justification: Any,
                     expires_at: Any) -> dict[str, Any]:
    justification = _text(justification, "justification", maximum=500)
    if len(justification) < 10:
        raise Invalid("justification is too short")
    try:
        exp = dt.datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
    except ValueError:
        raise Invalid("expires_at must be an ISO 8601 time") from None
    now = dt.datetime.now(dt.UTC)
    if exp.tzinfo is None or exp <= now or exp > now + dt.timedelta(days=MAX_OVERRIDE_DAYS):
        raise Invalid(f"expires_at must be in the future, with a time zone, within {MAX_OVERRIDE_DAYS} days")
    ap = _one(conn, "SELECT * FROM approvals WHERE id = %s", [_uuid(approval_id, "approval id")], "approval")
    f = _one(conn, "SELECT * FROM findings WHERE id = %s", [_uuid(finding_id, "finding id")], "finding")
    if ap["status"] != "pending" or ap["subject_type"] != "tool" or f["tool_id"] != ap["subject_id"]:
        raise Conflict("the finding does not belong to a pending tool approval")
    row = _one(conn, "INSERT INTO overrides (tenant_id, approval_id, finding_id, justification, expires_at, requested_by) "
                     "VALUES (%s, %s, %s, %s, %s, %s) RETURNING *", [actor.tenant, ap["id"], f["id"], justification, exp, actor.user_id])
    emit(conn, actor.tenant, "override.requested", actor.label, subject_type="finding", subject_id=f["id"])
    return _row(row)


def approve_override(conn: Conn, actor: Actor, override_id: str) -> dict[str, Any]:
    ov = _one(conn, "SELECT * FROM overrides WHERE id = %s FOR UPDATE", [_uuid(override_id, "override id")], "override")
    if ov["expires_at"] <= dt.datetime.now(dt.UTC):
        raise Conflict("override has expired")
    try:
        with conn.transaction():
            conn.execute("INSERT INTO override_approvers (tenant_id, override_id, approver_user_id) VALUES (%s, %s, %s)",
                         [actor.tenant, ov["id"], actor.user_id])
    except pgerr.UniqueViolation:
        raise Conflict("this approver already approved the override") from None
    except pgerr.IntegrityConstraintViolation:
        raise SeparationOfDuties("a requester cannot approve their own override") from None
    n = scalar(conn, "SELECT count(DISTINCT approver_user_id) AS n FROM override_approvers WHERE override_id = %s", [ov["id"]], "n")
    if n >= 2 and ov["effective_at"] is None:
        conn.execute("UPDATE overrides SET effective_at = now() WHERE id = %s", [ov["id"]])
    emit(conn, actor.tenant, "override.approved", actor.label, subject_type="finding", subject_id=ov["finding_id"], excerpt=f"{n} of 2 approvers")
    return {**_j(_one(conn, "SELECT * FROM overrides WHERE id = %s", [ov["id"]])), "approvers": n}


# ------------------------------------------------------------------ reads

def _page(limit: Any) -> int:
    return max(1, min(int(limit), 200)) if str(limit).isdigit() else 50


LISTABLE = frozenset({"agents", "mcp_servers", "tools", "findings", "approvals", "classification_levels", "audit_events"})


def list_rows(conn: Conn, table: str, *, where: str = "TRUE", params: list[Any] | None = None, limit: Any = 50,
              after: Any = None) -> list[dict[str, Any]]:
    if table not in LISTABLE:  # the name is interpolated into SQL below, so it must come from this fixed set
        raise ValueError("table is not listable")
    sql = f"SELECT * FROM {table} WHERE {where}"  # noqa: S608 - table is from the fixed set above
    p = list(params or [])
    if after and table != "audit_events":
        sql += " AND id > %s"
        p.append(_uuid(after, "page token"))
    sql += " ORDER BY seq" if table == "audit_events" else " ORDER BY id"
    sql += " LIMIT %s"
    p.append(_page(limit))
    return [_j(r) for r in conn.execute(sql, p)]


def get_row(conn: Conn, table: str, row_id: str, what: str) -> dict[str, Any]:
    if table not in {"agents", "mcp_servers", "tools"}:
        raise ValueError("table is not readable by id")
    return _row(_one(conn, f"SELECT * FROM {table} WHERE id = %s", [_uuid(row_id, f"{what} id")], what))  # noqa: S608


def tool_versions(conn: Conn, tool_id: str) -> list[dict[str, Any]]:
    _one(conn, "SELECT id FROM tools WHERE id = %s", [_uuid(tool_id, "tool id")], "tool")
    return [_j(r) for r in conn.execute("SELECT * FROM tool_versions WHERE tool_id = %s ORDER BY version_no", [tool_id])]


def tool_diff(conn: Conn, tool_id: str) -> dict[str, Any]:
    """Field-level difference between the approved definition and the one waiting for approval (FR-DRIFT-4)."""
    tool = _one(conn, "SELECT * FROM tools WHERE id = %s", [_uuid(tool_id, "tool id")], "tool")
    cur = conn.execute("SELECT canonical_json FROM tool_versions WHERE id = %s", [tool["current_version_id"]]).fetchone() if tool["current_version_id"] else None
    pend = conn.execute("SELECT id, proposed_definition FROM approvals WHERE subject_type = 'tool' AND subject_id = %s AND status = 'pending'", [tool["id"]]).fetchone()
    before, after = (cur["canonical_json"] if cur else {}), (pend["proposed_definition"] if pend else {})
    changes = [{"field": k, "change": "added" if k not in before else "removed" if k not in after else "changed",
                "before": before.get(k), "after": after.get(k)}
               for k in sorted(set(before) | set(after)) if before.get(k) != after.get(k) or (k in before) != (k in after)]
    return {"tool_id": str(tool["id"]), "approval_id": str(pend["id"]) if pend else None, "has_pending": pend is not None, "changes": changes}
