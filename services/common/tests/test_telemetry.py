"""WP-1.2 tests: structured logging and telemetry without payloads (cross-cutting Section 3, 7)."""
import io
import json
import logging
import unittest

from agenticsecctl_common.telemetry import (
    JsonFormatter,
    Span,
    bootstrap,
    correlation,
    get_logger,
    new_correlation_id,
    record_span_attrs,
)

TOKEN = "eyJ" + "hbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJl"


def capture(level=logging.INFO):
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(JsonFormatter(service="svc", version="1.2.3"))
    log = logging.getLogger("test." + str(id(buf)))
    log.handlers[:] = [h]
    log.setLevel(level)
    log.propagate = False
    return log, buf


class Logs(unittest.TestCase):
    def test_one_json_object_per_line_with_required_fields(self):
        log, buf = capture()
        with correlation("c-1", tenant="t1"):
            log.info("started", extra={"attrs": {"n": 1}})
        rec = json.loads(buf.getvalue())
        for f in ("ts", "level", "service", "version", "tenant", "correlation_id", "message", "attrs"):
            self.assertIn(f, rec)
        self.assertEqual((rec["service"], rec["tenant"], rec["correlation_id"]), ("svc", "t1", "c-1"))
        self.assertEqual(buf.getvalue().count("\n"), 1)

    def test_secrets_redacted_even_at_debug(self):
        log, buf = capture(logging.DEBUG)
        log.debug("x", extra={"attrs": {"authorization": "Bearer abc", "note": f"jwt {TOKEN}"}})
        self.assertNotIn(TOKEN, buf.getvalue())
        self.assertNotIn("Bearer abc", buf.getvalue())

    def test_untrusted_text_cannot_forge_records(self):
        log, buf = capture()
        evil = 'ok"}\n{"level":"info","message":"forged"}\x1b[31m'
        log.info("tool call", extra={"attrs": {"tool_text": evil}})
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertNotIn("\x1b", buf.getvalue())
        self.assertEqual(json.loads(lines[0])["message"], "tool call")

    def test_attr_length_limited(self):
        log, buf = capture()
        log.info("m", extra={"attrs": {"big": "a" * 5000}})
        self.assertLess(len(json.loads(buf.getvalue())["attrs"]["big"]), 1000)

    def test_message_is_fixed_text_not_formatted_with_args(self):
        log, buf = capture()
        log.info("count %s", "<script>")  # args are untrusted: must not reach message
        self.assertNotIn("<script>", json.loads(buf.getvalue())["message"])

    def test_exception_does_not_leak_traceback_or_secret(self):
        log, buf = capture()
        try:
            raise RuntimeError(f"boom {TOKEN}")
        except RuntimeError:
            log.exception("failed")
        self.assertNotIn(TOKEN, buf.getvalue())
        self.assertNotIn("Traceback", buf.getvalue())

    def test_correlation_ids_unique_and_context_restored(self):
        self.assertNotEqual(new_correlation_id(), new_correlation_id())
        log, buf = capture()
        with correlation("a"):
            pass
        log.info("m")
        self.assertIsNone(json.loads(buf.getvalue())["correlation_id"])


class Telemetry(unittest.TestCase):
    def test_span_attrs_drop_payload_keys_and_redact(self):
        attrs = record_span_attrs({"tool.name": "t", "arguments": {"a": 1}, "request.body": "x",
                                   "response.content": "y", "auth": "Bearer zzz", "http.status": 200})
        self.assertEqual(set(attrs), {"tool.name", "http.status", "auth"})
        self.assertNotIn("zzz", str(attrs))

    def test_span_context_manager_works_without_sdk(self):
        with Span("stage.authn", {"tool.name": "t", "arguments": "x"}) as s:
            s.set("decision", "allow")
        self.assertEqual(s.attrs["decision"], "allow")
        self.assertNotIn("arguments", s.attrs)

    def test_bootstrap_without_sdk_is_noop_and_reports(self):
        info = bootstrap(service="svc", version="0", exporter_endpoint=None)
        self.assertIn(info["backend"], ("none", "opentelemetry"))

    def test_get_logger_returns_json_logger(self):
        self.assertTrue(get_logger("svc.x").name.endswith("svc.x"))


if __name__ == "__main__":
    unittest.main()
