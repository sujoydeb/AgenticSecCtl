"""Structured logging and telemetry bootstrap (WP-1.2, cross-cutting design Sections 3 and 7).

Logs: one JSON object per line, fixed message text, untrusted values only in
length-limited, escaped ``attrs``, redaction always on (debug does not disable it).
Spans never carry payloads. OpenTelemetry is used when it is installed; otherwise
the span helpers are no-ops. The OpenTelemetry path is not exercised by the tests
because the SDK is not a pinned dependency yet.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from .redact import escape_untrusted, redact

_cid: contextvars.ContextVar[str | None] = contextvars.ContextVar("correlation_id", default=None)
_tenant: contextvars.ContextVar[str | None] = contextvars.ContextVar("tenant", default=None)
ATTR_LIMIT = 500
_PAYLOAD_TOKENS = {"arguments", "args", "body", "content", "payload", "prompt", "text",
                   "input", "output", "result"}
_SAFE_SUFFIX = ("digest", "hash", "size", "count", "bytes")
_tracer: Any = None


def new_correlation_id() -> str:
    return uuid.uuid4().hex


@contextlib.contextmanager
def correlation(cid: str, tenant: str | None = None):
    t1, t2 = _cid.set(cid), _tenant.set(tenant)
    try:
        yield
    finally:
        _cid.reset(t1)
        _tenant.reset(t2)


def _clean(v: Any) -> Any:
    v = redact(v)
    if isinstance(v, str):
        return escape_untrusted(v, ATTR_LIMIT)
    if isinstance(v, dict):
        return {escape_untrusted(str(k), 100): _clean(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_clean(x) for x in v]
    return v if isinstance(v, (int, float, bool)) or v is None else escape_untrusted(str(v), ATTR_LIMIT)


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, version: str):
        super().__init__()
        self.service, self.version = service, version

    def format(self, record: logging.LogRecord) -> str:
        attrs = dict(getattr(record, "attrs", {}) or {})
        event = attrs.pop("event", None)
        if record.exc_info and record.exc_info[0] is not None:
            attrs["exc_type"] = record.exc_info[0].__name__  # never the message or the traceback
        # record.args are untrusted by rule: they are never formatted into the message
        message = record.msg if isinstance(record.msg, str) else "log"
        out = {"ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
               "level": record.levelname.lower(), "service": self.service, "version": self.version,
               "tenant": _tenant.get(), "correlation_id": _cid.get(), "trace_id": None,
               "event": event, "message": escape_untrusted(message, ATTR_LIMIT), "attrs": _clean(attrs)}
        return json.dumps(out, separators=(",", ":"), ensure_ascii=True)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def configure_logging(service: str, version: str, level: int = logging.INFO, stream=None) -> None:
    h = logging.StreamHandler(stream)
    h.setFormatter(JsonFormatter(service, version))
    root = logging.getLogger()
    root.handlers[:] = [h]
    root.setLevel(level)


def record_span_attrs(attrs: dict[str, Any]) -> dict[str, Any]:
    """Drop payload-bearing attributes and redact the rest."""
    kept = {}
    for k, v in attrs.items():
        parts = set(re.split(r"[._\-]", k.lower()))
        if parts & _PAYLOAD_TOKENS and not k.lower().endswith(_SAFE_SUFFIX):
            continue
        kept[k] = redact(v)
    return kept


class Span:
    def __init__(self, name: str, attrs: dict[str, Any] | None = None):
        self.name, self.attrs, self._otel = name, record_span_attrs(attrs or {}), None

    def set(self, key: str, value: Any) -> None:
        self.attrs.update(record_span_attrs({key: value}))

    def __enter__(self) -> Span:
        if _tracer is not None:  # pragma: no cover - needs the SDK
            self._otel = _tracer.start_as_current_span(self.name, attributes=self.attrs)
            self._otel.__enter__()
        return self

    def __exit__(self, *exc) -> bool:
        if self._otel is not None:  # pragma: no cover
            self._otel.__exit__(*exc)
        return False


def bootstrap(*, service: str, version: str, exporter_endpoint: str | None) -> dict[str, str]:
    """Set up OpenTelemetry when available and an endpoint is configured; otherwise no-op."""
    global _tracer
    if not exporter_endpoint:
        return {"backend": "none"}
    try:  # pragma: no cover - needs the SDK
        from opentelemetry import trace
        _tracer = trace.get_tracer(service, version)
        return {"backend": "opentelemetry"}
    except ImportError:
        return {"backend": "none"}
