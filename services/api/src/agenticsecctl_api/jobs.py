"""Scan job lifecycle for the scanner worker (WP-1.7, IG-6; FR-SCAN-1/2/6, CTL-02).

The worker talks only to the API. A job is claimed through the dispatcher role (the one narrow cross-tenant
view, migration 0003), with a lease. From then on every step runs in the job's own tenant with the normal
application role. A lease that runs out puts the job back in the queue until ``max_attempts``, then it fails with
a recorded reason and an ``import.failed`` event. Only the worker that holds the lease can renew it, finish the
job or report a failure, and only while the lease is valid.

What the API does not take on trust from the worker: the definitions are hashed here, the risk score is
recomputed here from the findings (the same weights, one definition in ``common``), severities are checked
against the known set, and a rule-set version cannot be reused with different content. A compromised worker can
still *omit* findings; the tool then still needs a human approval (accepted residual risk, threat A).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from agenticsecctl_common.contracts import SEVERITIES, risk_score
from agenticsecctl_common.redact import escape_untrusted, redact

from .db import Conn, Database
from .errors import Conflict, Invalid, NotFound
from .events import emit
from .registry import Actor, _j, _one, _uuid, scalar, submit_definitions

LEASE_SECONDS = 120          # proposal for the scan job lease (PAR-O-01 family), confirmed in the parameter register
MAX_LEASE_SECONDS = 900
MAX_TOOLS, MAX_FINDINGS_PER_TOOL, MAX_FINDINGS_PER_JOB = 500, 100, 5000
_REASON = re.compile(r"^[a-z0-9:_.-]{1,60}$")
_WORKER = re.compile(r"^[A-Za-z0-9:_.@-]{1,100}$")


def worker_id(client_id: str, instance: Any) -> str:
    if not isinstance(instance, str) or not _WORKER.match(instance):
        raise Invalid("worker_id is not valid")
    return f"{client_id}:{instance}"


# ------------------------------------------------------------------ claim (dispatcher role, no tenant)

def claim(dispatch: Database, worker: str, lease_seconds: int = LEASE_SECONDS) -> dict[str, Any] | None:
    """Claim the oldest claimable job. ``FOR UPDATE SKIP LOCKED`` means two workers never get the same job."""
    lease = max(10, min(int(lease_seconds), MAX_LEASE_SECONDS))
    with dispatch.unscoped() as c:
        row = c.execute(
            "UPDATE scan_jobs SET status = 'claimed', claimed_by = %s, lease_expires_at = now() + make_interval(secs => %s), attempts = attempts + 1 "
            "WHERE id = (SELECT id FROM scan_jobs WHERE attempts < max_attempts AND (status = 'queued' OR (status = 'claimed' AND lease_expires_at < now())) "
            "ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1) "
            "RETURNING id, tenant_id, server_id, kind, attempts, max_attempts, lease_expires_at", [worker, lease]).fetchone()
    return _j(row) if row else None


def exhausted(dispatch: Database) -> list[dict[str, Any]]:
    """Jobs whose lease ran out on their last allowed attempt."""
    with dispatch.unscoped() as c:
        return [_j(r) for r in c.execute("SELECT id, tenant_id FROM scan_jobs WHERE status = 'claimed' AND lease_expires_at < now() AND attempts >= max_attempts")]


def tenant_of(dispatch: Database, job_id: str) -> str:
    with dispatch.unscoped() as c:
        row = c.execute("SELECT tenant_id FROM scan_jobs WHERE id = %s", [_uuid(job_id, "job id")]).fetchone()
    if row is None:
        raise NotFound("job")
    return str(row["tenant_id"])


def fail_exhausted(conn: Conn, tenant: str, job_id: str) -> bool:
    """In the job's tenant: fail a job whose last attempt's lease expired and record the event, atomically."""
    row = conn.execute("UPDATE scan_jobs SET status = 'failed', failure_reason = 'lease-expired' WHERE id = %s AND status = 'claimed' "
                       "AND lease_expires_at < now() AND attempts >= max_attempts RETURNING server_id", [job_id]).fetchone()
    if row:
        emit(conn, tenant, "import.failed", "service:scanner", subject_type="server", subject_id=row["server_id"], excerpt="lease-expired after the last attempt")
    return bool(row)


# ------------------------------------------------------------------ in the job's tenant

def _held(conn: Conn, job_id: str, worker: str) -> dict[str, Any]:
    job = _one(conn, "SELECT * FROM scan_jobs WHERE id = %s FOR UPDATE", [_uuid(job_id, "job id")], "job")
    live = bool(scalar(conn, "SELECT %s::timestamptz > now() AS live", [job["lease_expires_at"]], "live")) if job["lease_expires_at"] else False
    if job["status"] != "claimed" or job["claimed_by"] != worker or not live:
        raise Conflict("the job is not held by this worker")
    return job


def details(conn: Conn, job_id: str) -> dict[str, Any]:
    job = _one(conn, "SELECT * FROM scan_jobs WHERE id = %s", [job_id], "job")
    server = _one(conn, "SELECT id, namespace, url FROM mcp_servers WHERE id = %s", [job["server_id"]], "server")
    return {"job_id": str(job["id"]), "kind": job["kind"], "attempts": job["attempts"], "max_attempts": job["max_attempts"],
            "lease_expires_at": job["lease_expires_at"].isoformat(), "server_id": str(server["id"]), "namespace": server["namespace"], "url": server["url"]}


def renew(conn: Conn, job_id: str, worker: str, lease_seconds: int = LEASE_SECONDS) -> dict[str, Any]:
    job = _held(conn, job_id, worker)
    lease = max(10, min(int(lease_seconds), MAX_LEASE_SECONDS))
    row = _one(conn, "UPDATE scan_jobs SET lease_expires_at = now() + make_interval(secs => %s) WHERE id = %s RETURNING lease_expires_at", [lease, job["id"]])
    return {"lease_expires_at": row["lease_expires_at"].isoformat()}


def fail(conn: Conn, job_id: str, worker: str, reason: Any, retryable: Any) -> dict[str, Any]:
    if not isinstance(reason, str) or not _REASON.match(reason) or not isinstance(retryable, bool):
        raise Invalid("reason must be a short code and retryable a boolean")
    job = _held(conn, job_id, worker)
    if retryable and job["attempts"] < job["max_attempts"]:
        conn.execute("UPDATE scan_jobs SET status = 'queued', claimed_by = NULL, lease_expires_at = NULL, failure_reason = %s WHERE id = %s", [reason, job["id"]])
        return {"status": "queued", "attempts": job["attempts"]}
    conn.execute("UPDATE scan_jobs SET status = 'failed', failure_reason = %s WHERE id = %s", [reason, job["id"]])
    emit(conn, job["tenant_id"], "import.failed", "service:scanner", subject_type="server", subject_id=job["server_id"], excerpt=reason)
    return {"status": "failed", "attempts": job["attempts"]}


def _check_result(result: Any) -> tuple[dict[str, str], list[dict[str, Any]]]:
    if not isinstance(result, dict) or set(result) - {"rule_set", "tools"}:
        raise Invalid("result must be an object with a rule set and tools only")
    rs, tools = result.get("rule_set"), result.get("tools")
    if (not isinstance(rs, dict) or set(rs) - {"version", "hash"} or not isinstance(rs.get("version"), str) or not 0 < len(rs["version"]) <= 60
            or not isinstance(rs.get("hash"), str) or not re.fullmatch(r"[0-9a-f]{64}", rs["hash"])):
        raise Invalid("rule_set needs a version and a SHA-256 hash")
    if not isinstance(tools, list) or not 1 <= len(tools) <= MAX_TOOLS:
        raise Invalid(f"tools must be a list of 1 to {MAX_TOOLS} entries")
    total = 0
    for t in tools:
        if (not isinstance(t, dict) or set(t) - {"definition", "findings"} or not isinstance(t.get("definition"), dict)
                or not isinstance(t.get("findings", []), list)):
            raise Invalid("every tool needs a definition and a findings list")
        fs = t.get("findings", [])
        total += len(fs)
        if len(fs) > MAX_FINDINGS_PER_TOOL or total > MAX_FINDINGS_PER_JOB:
            raise Invalid("too many findings")
        for f in fs:
            if (not isinstance(f, dict) or set(f) - {"rule_id", "severity", "location", "evidence", "confidence"}
                    or not isinstance(f.get("rule_id"), str) or not re.fullmatch(r"[A-Z][A-Z0-9-]{1,40}", f["rule_id"])
                    or f.get("severity") not in SEVERITIES or not isinstance(f.get("location"), str) or len(f["location"]) > 300
                    or not isinstance(f.get("evidence", ""), str) or isinstance(f.get("confidence"), bool)
                    or not isinstance(f.get("confidence"), (int, float)) or not 0 <= f["confidence"] <= 1):
                raise Invalid("a finding is malformed")
    return rs, tools


def complete(conn: Conn, job_id: str, worker: str, result: Any) -> dict[str, Any]:
    job = _held(conn, job_id, worker)
    rs, tools = _check_result(result)
    server = _one(conn, "SELECT * FROM mcp_servers WHERE id = %s", [job["server_id"]], "server")
    if server["owner_user_id"] is None:
        raise Conflict("the server has no owner to attribute the submission to")
    tenant = str(job["tenant_id"])
    actor = Actor(str(server["owner_user_id"]), tenant, via="scanner")

    row = conn.execute("SELECT id, content_hash FROM rule_sets WHERE version = %s", [rs["version"]]).fetchone()
    if row is None:
        row = _one(conn, "INSERT INTO rule_sets (tenant_id, version, content_hash) VALUES (%s, %s, %s) RETURNING id, content_hash", [tenant, rs["version"], bytes.fromhex(rs["hash"])])
    elif bytes(row["content_hash"]) != bytes.fromhex(rs["hash"]):
        raise Conflict("a rule-set version cannot be reused with different content")

    submitted = submit_definitions(conn, actor, str(server["id"]), [t["definition"] for t in tools])
    scores = [risk_score([(f["severity"], float(f["confidence"])) for f in t.get("findings", [])]) for t in tools]
    scan = _one(conn, "INSERT INTO scans (tenant_id, server_id, rule_set_id, risk_score, status, finished_at) VALUES (%s, %s, %s, %s, 'completed', now()) RETURNING id",
                [tenant, server["id"], row["id"], max(scores) if scores else 0])
    created = 0
    for sub, t in zip(submitted, tools, strict=True):
        for f in t.get("findings", []):
            loc = escape_untrusted(redact(f["location"]), 300)
            ev = escape_untrusted(redact(f.get("evidence", "")), 500)
            if conn.execute("SELECT 1 FROM findings WHERE tool_id = %s AND rule_id = %s AND location = %s AND status = 'open' AND severity = %s",
                            [sub["tool_id"], f["rule_id"], loc, f["severity"]]).fetchone():
                continue  # the same open finding is not recorded twice (a re-scan with unchanged result)
            conn.execute("INSERT INTO findings (tenant_id, scan_id, tool_id, rule_id, severity, location, evidence_excerpt, confidence) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                         [tenant, scan["id"], sub["tool_id"], f["rule_id"], f["severity"], loc, ev, round(float(f["confidence"]), 3)])
            emit(conn, tenant, "finding.created", actor.label, subject_type="tool", subject_id=sub["tool_id"], excerpt=f"{f['severity']} {f['rule_id']}")
            created += 1
    conn.execute("UPDATE scan_jobs SET status = 'done', result_scan_id = %s, failure_reason = NULL WHERE id = %s", [scan["id"], job["id"]])
    emit(conn, tenant, "scan.completed", actor.label, subject_type="server", subject_id=server["id"], excerpt=f"{len(tools)} tools, {created} new findings, rule set {rs['version']}")
    digest = hashlib.sha256(rs["hash"].encode()).hexdigest()[:12]
    return {"scan_id": str(scan["id"]), "tools": [{k: s[k] for k in ("tool_id", "name", "state", "approval_id")} for s in submitted],
            "new_findings": created, "risk_score": max(scores) if scores else 0, "rule_set": rs["version"], "rule_set_ref": digest}
