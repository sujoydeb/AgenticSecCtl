"""The scanner worker loop (WP-1.7, IG-6).

It has no database credentials and no secrets of its own beyond a short-lived token for the API: it claims a job
from the API, imports the server's tool list through the guarded client, scans every definition and posts the
result (or a failure with a stable reason code) back to the API. Anything the imported server sends is treated as
untrusted data from the first byte; nothing it sends is executed, fetched or written anywhere but into the result.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any, Protocol

from agenticsecctl_common.http import GuardedClient, SsrfRejected

from .classifier import Classifier
from .importer import ImportFailed, ImportLimits, fetch_tool_definitions
from .scan import scan_tool

log = logging.getLogger("agenticsecctl.scanner")


class ApiError(Exception):
    def __init__(self, status: int):
        super().__init__(f"api returned {status}")
        self.status = status


class LeaseLost(ApiError):
    """The API says this worker no longer holds the job (409): stop, another attempt owns it now."""


class JobApi(Protocol):
    def claim(self, instance: str) -> dict[str, Any] | None: ...
    def renew(self, job_id: str, instance: str) -> None: ...
    def result(self, job_id: str, instance: str, result: dict[str, Any]) -> dict[str, Any]: ...
    def failure(self, job_id: str, instance: str, reason: str, retryable: bool) -> dict[str, Any]: ...


class HttpJobApi:
    """Talks to ``/v1/internal/scan-jobs/*`` through the guarded client (the API host needs an exception entry)."""

    def __init__(self, client: GuardedClient, base_url: str, token: Callable[[], str], *, timeout: float = 30.0):
        self._c, self._base, self._token, self._timeout = client, base_url.rstrip("/"), token, timeout

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            r = self._c.request("POST", f"{self._base}/v1/internal/scan-jobs{path}", body=json.dumps(payload).encode(), timeout=self._timeout,
                                total_timeout=self._timeout * 2, max_bytes=2_000_000,
                                headers={"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"})
        except SsrfRejected as exc:
            raise ApiError(0) from exc
        if r.status == 409:
            raise LeaseLost(409)
        if r.status != 200:
            raise ApiError(r.status)
        out: dict[str, Any] = json.loads(r.body)
        return out

    def claim(self, instance: str) -> dict[str, Any] | None:
        return self._post("/claim", {"worker_id": instance}).get("job")

    def renew(self, job_id: str, instance: str) -> None:
        self._post(f"/{job_id}/renew", {"worker_id": instance})

    def result(self, job_id: str, instance: str, result: dict[str, Any]) -> dict[str, Any]:
        return self._post(f"/{job_id}/result", {"worker_id": instance, "result": result})

    def failure(self, job_id: str, instance: str, reason: str, retryable: bool) -> dict[str, Any]:
        return self._post(f"/{job_id}/failure", {"worker_id": instance, "reason": reason, "retryable": retryable})


def run_once(api: JobApi, client: GuardedClient, instance: str, *, limits: ImportLimits = ImportLimits(),  # noqa: B008
             classifier: Classifier | None = None) -> str:
    """One claim-import-scan-report cycle. Returns idle, done, failed, retry or lease-lost."""
    job = api.claim(instance)
    if job is None:
        return "idle"
    job_id = job["job_id"]
    try:
        tools = fetch_tool_definitions(client, job["url"], limits)
        results = [scan_tool(t, classifier=classifier) for t in tools]
        api.renew(job_id, instance)  # scanning is quick; renewing before the (possibly slow) upload keeps the lease valid
        payload = {"rule_set": {"version": results[0].rule_set_version, "hash": results[0].rule_set_hash} if results else None,
                   "tools": [{"definition": t, "findings": [f.as_dict() for f in r.findings]} for t, r in zip(tools, results, strict=True)]}
        if not tools:
            api.failure(job_id, instance, "no-tools", False)
            return "failed"
        api.result(job_id, instance, payload)
        return "done"
    except ImportFailed as exc:
        log.info("import failed: %s", exc.reason)
        return _report(api, job_id, instance, exc.reason, exc.retryable)
    except LeaseLost:
        log.warning("lease lost for job %s", job_id)
        return "lease-lost"
    except Exception:  # noqa: BLE001 - a bug or a hostile input must not kill the worker or leave the job claimed
        log.exception("unexpected error while processing a job")
        return _report(api, job_id, instance, "internal-error", True)


def _report(api: JobApi, job_id: str, instance: str, reason: str, retryable: bool) -> str:
    try:
        out = api.failure(job_id, instance, reason.replace("guard:", "guard-"), retryable)
    except LeaseLost:
        return "lease-lost"
    return "retry" if out.get("status") == "queued" else "failed"
