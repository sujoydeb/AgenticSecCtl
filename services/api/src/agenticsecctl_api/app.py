"""Management API (WP-1.6): FastAPI routes over the registry service.

Order of work for every request: correlation id, authenticate (token, then principal), authorize the route
template against the role table, require the Idempotency-Key where the specification does, only then read and
validate the body, run the service function in one tenant-scoped transaction, and record refusals (separation of
duties, SSRF, authorization) as audit events in a separate transaction so a rolled-back request still leaves a
trace. Errors are RFC 9457 problem details from the fixed catalogue; no input text is ever echoed.
"""
from __future__ import annotations

import contextlib
import json
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.concurrency import run_in_threadpool

from agenticsecctl_common.auth.jwt import AuthError, TokenValidator
from agenticsecctl_common.auth.principals import IdentityDirectory, IdentityError, Kind, Principal
from agenticsecctl_common.auth.roles import Forbidden, authorize
from agenticsecctl_common.errors import CATALOGUE, problem_details
from agenticsecctl_common.http import Guard

from . import audit, jobs, registry
from .db import Database
from .errors import DomainError
from .events import emit
from .registry import Actor
from .roles_db import DbRoleStore

log = logging.getLogger("agenticsecctl.api")
MAX_BODY = 1_000_000          # user endpoints
MAX_INTERNAL_BODY = 8_000_000 # scanner results carry whole tool definitions
IDEMPOTENT = {("POST", "/agents"), ("POST", "/servers"), ("POST", "/servers/{id}/imports"), ("POST", "/servers/{id}/definitions"),
              ("POST", "/approvals/{id}/decision"), ("POST", "/approvals/{id}/overrides"), ("POST", "/overrides/{id}/approvals")}


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_max_length=2000)


class AgentIn(_In):
    name: str
    identity_ref: str
    environment: str = "dev"
    criticality: str = "medium"


class ServerIn(_In):
    namespace: str
    url: str
    environment: str = "dev"
    criticality: str = "medium"


class DefinitionsIn(_In):
    model_config = ConfigDict(extra="forbid", str_max_length=20000)
    tools: list[dict[str, Any]]


class DecisionIn(_In):
    decision: str
    action_class: str | None = None
    reason: str | None = None


class QuarantineIn(_In):
    reason: str


class ClaimIn(_In):
    worker_id: str
    lease_seconds: int = jobs.LEASE_SECONDS


class RenewIn(ClaimIn):
    pass


class ResultIn(_In):
    model_config = ConfigDict(extra="forbid", str_max_length=200_000)
    worker_id: str
    result: dict[str, Any]


class FailureIn(_In):
    worker_id: str
    reason: str
    retryable: bool


class OverrideIn(_In):
    finding_id: str
    justification: str
    expires_at: str


def create_app(*, db: Database, audit_db: Database | None, validator: TokenValidator, directory: IdentityDirectory,
               guard: Guard, dispatch_db: Database | None = None, user_clients: frozenset[str] = frozenset(), drain_inline: bool = True,
               clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> FastAPI:
    app = FastAPI(title="AgenticSecCtl management API", docs_url=None, redoc_url=None, openapi_url=None)
    store = DbRoleStore(db)

    def problem(code: str, cid: str, headers: dict[str, str] | None = None) -> JSONResponse:
        status = CATALOGUE.get(code, CATALOGUE["internal"])[0]
        h = {"X-Correlation-ID": cid, "Content-Type": "application/problem+json", **(headers or {})}
        if status == 401:
            h["WWW-Authenticate"] = "Bearer"
        return JSONResponse(problem_details(code, correlation_id=cid), status_code=status, headers=h)

    def authenticate(request: Request) -> Principal:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError("malformed")
        principal = directory.resolve(validator.validate(token))
        return principal

    def deny_event(principal: Principal | None, event: str, excerpt: str) -> None:
        """Record a refusal in its own transaction; never lets a logging failure change the response."""
        if principal is None or principal.tenant is None:
            return
        try:
            with db.transaction(principal.tenant) as c:
                emit(c, principal.tenant, event, f"user:{principal.user_id}" if principal.user_id else f"client:{principal.client_id}", excerpt=excerpt)
        except Exception:  # noqa: BLE001
            log.exception("could not record a refusal")

    def drain(tenant: str) -> None:
        if drain_inline and audit_db is not None:
            try:
                audit.drain(audit_db, tenant)
            except Exception:  # noqa: BLE001 - the outbox keeps the events; the next drain retries
                log.exception("audit drain failed")

    async def handle(request: Request, method: str, template: str, fn: Callable[..., Any], *, model: type[BaseModel] | None = None,
                     status: int = 200, resource: tuple[str, str] | None = None, write: bool = False, pass_body: bool = True) -> JSONResponse:
        cid = request.headers.get("x-correlation-id", "")
        cid = cid if len(cid) <= 64 and all(ch.isalnum() or ch in "-_" for ch in cid) and cid else str(uuid.uuid4())
        principal: Principal | None = None
        try:
            try:
                principal = authenticate(request)
            except (AuthError, IdentityError):
                return problem("unauthenticated", cid)
            try:
                authorize(principal, method, template, store, now=clock(), resource=resource)
            except Forbidden:
                deny_event(principal, "authz.deny", f"{method} {template}")
                return problem("forbidden", cid)
            if principal.kind is not Kind.USER or principal.tenant is None or principal.user_id is None:
                return problem("forbidden", cid)
            key = request.headers.get("idempotency-key")
            if (method, template) in IDEMPOTENT and (not key or len(key) > 100):
                return problem("invalid-request", cid)
            body: Any = None
            if model is not None:
                try:
                    raw = await request.body()
                    if len(raw) > MAX_BODY:
                        return problem("invalid-request", cid)
                    body = model.model_validate(json.loads(raw or b"null"))
                except (ValueError, ValidationError):
                    return problem("invalid-request", cid)
            actor = Actor(principal.user_id, principal.tenant)
            tenant = principal.tenant

            def work() -> Any:
                with db.transaction(tenant) as conn:
                    kwargs: dict[str, Any] = {"key": key} if template == "/approvals/{id}/decision" else {}
                    return fn(conn, actor, body, **kwargs) if pass_body else fn(conn, actor, **kwargs)
            result = await run_in_threadpool(work)
        except DomainError as exc:
            if exc.audit:
                deny_event(principal, exc.audit, f"{method} {template}: {exc.detail}"[:180])
                if principal is not None and principal.tenant:
                    await run_in_threadpool(drain, principal.tenant)
            return problem(exc.code, cid)
        except Exception:  # noqa: BLE001 - fail closed with a generic error; details go to the log only
            log.exception("unhandled error")
            return problem("internal", cid)
        if write:
            await run_in_threadpool(drain, tenant)
        return JSONResponse(result, status_code=status, headers={"X-Correlation-ID": cid})

    def q(request: Request, name: str, default: Any = None) -> Any:
        return request.query_params.get(name, default)

    # ---------------------------------------------------------------- health (unauthenticated)
    @app.get("/v1/health")
    async def health(request: Request) -> JSONResponse:
        cid = str(uuid.uuid4())
        try:
            def ping() -> None:
                with db.unscoped() as c:
                    c.execute("SELECT 1")
            await run_in_threadpool(ping)
        except Exception:  # noqa: BLE001
            return problem("not-ready", cid)
        return JSONResponse({"status": "ready"}, headers={"X-Correlation-ID": cid})

    # ---------------------------------------------------------------- agents
    @app.get("/v1/agents")
    async def agents_list(request: Request) -> JSONResponse:
        return await handle(request, "GET", "/agents", lambda c, a: {"items": registry.list_rows(c, "agents", limit=q(request, "limit", 50), after=q(request, "page_token"))}, pass_body=False)

    @app.get("/v1/agents/{agent_id}")
    async def agents_get(request: Request, agent_id: str) -> JSONResponse:
        return await handle(request, "GET", "/agents/{id}", lambda c, a: registry.get_row(c, "agents", agent_id, "agent"), resource=("agent", agent_id), pass_body=False)

    @app.post("/v1/agents")
    async def agents_create(request: Request) -> JSONResponse:
        return await handle(request, "POST", "/agents", lambda c, a, b: registry.register_agent(c, a, **b.model_dump()), model=AgentIn, status=201, write=True)

    # ---------------------------------------------------------------- servers
    @app.get("/v1/servers")
    async def servers_list(request: Request) -> JSONResponse:
        return await handle(request, "GET", "/servers", lambda c, a: {"items": registry.list_rows(c, "mcp_servers", limit=q(request, "limit", 50), after=q(request, "page_token"))}, pass_body=False)

    @app.post("/v1/servers")
    async def servers_create(request: Request) -> JSONResponse:
        return await handle(request, "POST", "/servers", lambda c, a, b: registry.register_server(c, a, guard=guard, **b.model_dump()), model=ServerIn, status=201, write=True)

    @app.post("/v1/servers/{server_id}/imports")
    async def servers_import(request: Request, server_id: str) -> JSONResponse:
        return await handle(request, "POST", "/servers/{id}/imports", lambda c, a: registry.enqueue_import(c, a, server_id), status=202, write=True, pass_body=False)

    @app.post("/v1/servers/{server_id}/definitions")
    async def servers_definitions(request: Request, server_id: str) -> JSONResponse:
        return await handle(request, "POST", "/servers/{id}/definitions", lambda c, a, b: {"items": registry.submit_definitions(c, a, server_id, b.tools)}, model=DefinitionsIn, status=202, write=True)

    # ---------------------------------------------------------------- tools
    @app.get("/v1/tools/{tool_id}")
    async def tools_get(request: Request, tool_id: str) -> JSONResponse:
        return await handle(request, "GET", "/tools/{id}", lambda c, a: registry.get_row(c, "tools", tool_id, "tool"), pass_body=False)

    @app.get("/v1/tools/{tool_id}/versions")
    async def tools_versions(request: Request, tool_id: str) -> JSONResponse:
        return await handle(request, "GET", "/tools/{id}/versions", lambda c, a: {"items": registry.tool_versions(c, tool_id)}, pass_body=False)

    @app.get("/v1/tools/{tool_id}/diff")
    async def tools_diff(request: Request, tool_id: str) -> JSONResponse:
        return await handle(request, "GET", "/tools/{id}/diff", lambda c, a: registry.tool_diff(c, tool_id), pass_body=False)

    @app.put("/v1/tools/{tool_id}/quarantine")
    async def tools_quarantine(request: Request, tool_id: str) -> JSONResponse:
        return await handle(request, "PUT", "/tools/{id}/quarantine", lambda c, a, b: registry.quarantine_tool(c, a, tool_id, b.reason), model=QuarantineIn, write=True)

    # ---------------------------------------------------------------- approvals
    @app.get("/v1/approvals")
    async def approvals_list(request: Request) -> JSONResponse:
        status = q(request, "status", "pending")
        if status not in ("pending", "approved", "rejected", "expired"):
            return problem("invalid-request", str(uuid.uuid4()))
        return await handle(request, "GET", "/approvals", lambda c, a: {"items": registry.list_rows(c, "approvals", where="status = %s", params=[status], limit=q(request, "limit", 50), after=q(request, "page_token"))}, pass_body=False)

    @app.post("/v1/approvals/{approval_id}/decision")
    async def approvals_decide(request: Request, approval_id: str) -> JSONResponse:
        def fn(c: Any, a: Actor, b: DecisionIn, key: str | None = None) -> Any:
            return registry.decide_approval(c, a, approval_id, decision=b.decision, action_class=b.action_class, reason=b.reason, key=key)
        return await handle(request, "POST", "/approvals/{id}/decision", fn, model=DecisionIn, write=True)

    @app.post("/v1/approvals/{approval_id}/overrides")
    async def overrides_request(request: Request, approval_id: str) -> JSONResponse:
        return await handle(request, "POST", "/approvals/{id}/overrides", lambda c, a, b: registry.request_override(c, a, approval_id, b.finding_id, b.justification, b.expires_at), model=OverrideIn, status=201, write=True)

    @app.post("/v1/overrides/{override_id}/approvals")
    async def overrides_approve(request: Request, override_id: str) -> JSONResponse:
        return await handle(request, "POST", "/overrides/{id}/approvals", lambda c, a: registry.approve_override(c, a, override_id), status=201, write=True, pass_body=False)

    # ---------------------------------------------------------------- findings, classification, audit
    @app.get("/v1/findings")
    async def findings_list(request: Request) -> JSONResponse:
        return await handle(request, "GET", "/findings", lambda c, a: {"items": registry.list_rows(c, "findings", limit=q(request, "limit", 50), after=q(request, "page_token"))}, pass_body=False)

    @app.get("/v1/classification-levels")
    async def levels_list(request: Request) -> JSONResponse:
        return await handle(request, "GET", "/classification-levels", lambda c, a: {"items": registry.list_rows(c, "classification_levels", limit=200)}, pass_body=False)

    @app.get("/v1/audit/events")
    async def audit_events(request: Request) -> JSONResponse:
        def fn(c: Any, a: Actor) -> Any:
            after = int(q(request, "after", 0)) if str(q(request, "after", 0)).isdigit() else 0
            rows = registry.list_rows(c, "audit_events", where="seq > %s", params=[after], limit=q(request, "limit", 50))
            return {"items": [{k: v for k, v in r.items() if k not in ("prev_hash", "hash")} | {"hash": r["hash"]} for r in rows]}
        return await handle(request, "GET", "/audit/events", fn, pass_body=False)

    @app.post("/v1/audit/verification")
    async def audit_verify(request: Request) -> JSONResponse:
        def fn(c: Any, a: Actor) -> Any:
            v = audit.verify(c, a.tenant)
            if not v.ok:
                emit(c, a.tenant, "audit.verify.failed", a.label, subject_type="audit_chain", subject_id=str(v.first_bad_seq), excerpt=f"{v.kind}: {v.detail}")
            return {"ok": v.ok, "checked": v.checked, "first_bad_seq": v.first_bad_seq, "kind": v.kind}
        if audit_db is not None:
            principal_tenant = None
            with contextlib.suppress(AuthError, IdentityError):  # an unauthenticated caller is refused by handle() below
                principal_tenant = authenticate(request).tenant
            if principal_tenant:  # chain what is waiting, so the check covers every event so far
                await run_in_threadpool(drain, principal_tenant)
        return await handle(request, "POST", "/audit/verification", fn, write=True, pass_body=False)

    # ---------------------------------------------------------------- internal: the scanner worker (machine identity only)
    async def handle_internal(request: Request, method: str, template: str, fn: Callable[[Principal, Any], Any], *,
                              model: type[BaseModel] | None = None) -> JSONResponse:
        cid = str(uuid.uuid4())
        if dispatch_db is None:
            return problem("not-ready", cid)
        try:
            try:
                principal = authenticate(request)
            except (AuthError, IdentityError):
                return problem("unauthenticated", cid)
            try:
                authorize(principal, method, template, store, now=clock())
            except Forbidden:
                return problem("forbidden", cid)
            body: Any = None
            if model is not None:
                try:
                    raw = await request.body()
                    if len(raw) > MAX_INTERNAL_BODY:
                        return problem("invalid-request", cid)
                    body = model.model_validate(json.loads(raw or b"null"))
                except (ValueError, ValidationError):
                    return problem("invalid-request", cid)
            result = await run_in_threadpool(fn, principal, body)
        except DomainError as exc:
            return problem(exc.code, cid)
        except Exception:  # noqa: BLE001
            log.exception("unhandled error")
            return problem("internal", cid)
        return JSONResponse(result, headers={"X-Correlation-ID": cid})

    @app.post("/v1/internal/scan-jobs/claim")
    async def job_claim(request: Request) -> JSONResponse:
        def fn(p: Principal, b: ClaimIn) -> Any:
            if dispatch_db is None:
                raise RuntimeError("dispatcher is not configured")
            worker = jobs.worker_id(p.client_id, b.worker_id)
            for e in jobs.exhausted(dispatch_db):  # jobs that ran out of attempts are failed before the next claim
                with db.transaction(e["tenant_id"]) as c:
                    jobs.fail_exhausted(c, e["tenant_id"], e["id"])
            job = jobs.claim(dispatch_db, worker, b.lease_seconds)
            if job is None:
                return {"job": None}
            with db.transaction(job["tenant_id"]) as c:
                return {"job": jobs.details(c, job["id"])}
        return await handle_internal(request, "POST", "/internal/scan-jobs/claim", fn, model=ClaimIn)

    def in_job_tenant(job_id: str, work: Callable[[Any], Any]) -> Any:
        if dispatch_db is None:
            raise RuntimeError("dispatcher is not configured")
        with db.transaction(jobs.tenant_of(dispatch_db, job_id)) as c:
            return work(c)

    @app.post("/v1/internal/scan-jobs/{job_id}/renew")
    async def job_renew(request: Request, job_id: str) -> JSONResponse:
        def fn(p: Principal, b: RenewIn) -> Any:
            w = jobs.worker_id(p.client_id, b.worker_id)
            return in_job_tenant(job_id, lambda c: jobs.renew(c, job_id, w, b.lease_seconds))
        return await handle_internal(request, "POST", "/internal/scan-jobs/{id}/renew", fn, model=RenewIn)

    @app.post("/v1/internal/scan-jobs/{job_id}/result")
    async def job_result(request: Request, job_id: str) -> JSONResponse:
        def fn(p: Principal, b: ResultIn) -> Any:
            w = jobs.worker_id(p.client_id, b.worker_id)
            out = in_job_tenant(job_id, lambda c: jobs.complete(c, job_id, w, b.result))
            if audit_db is not None and drain_inline:
                try:
                    audit.drain(audit_db, jobs.tenant_of(dispatch_db, job_id))  # type: ignore[arg-type]
                except Exception:  # noqa: BLE001
                    log.exception("audit drain failed")
            return out
        return await handle_internal(request, "POST", "/internal/scan-jobs/{id}/result", fn, model=ResultIn)

    @app.post("/v1/internal/scan-jobs/{job_id}/failure")
    async def job_failure(request: Request, job_id: str) -> JSONResponse:
        def fn(p: Principal, b: FailureIn) -> Any:
            w = jobs.worker_id(p.client_id, b.worker_id)
            out = in_job_tenant(job_id, lambda c: jobs.fail(c, job_id, w, b.reason, b.retryable))
            if audit_db is not None and drain_inline:
                try:
                    audit.drain(audit_db, jobs.tenant_of(dispatch_db, job_id))  # type: ignore[arg-type]
                except Exception:  # noqa: BLE001
                    log.exception("audit drain failed")
            return out
        return await handle_internal(request, "POST", "/internal/scan-jobs/{id}/failure", fn, model=FailureIn)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:  # last resort
        log.error("unhandled error: %s", type(exc).__name__)
        return problem("internal", str(uuid.uuid4()))

    return app
