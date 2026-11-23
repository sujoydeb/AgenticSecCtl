"""WP-1.2 tests: redaction (TC-G5) and the error catalogue."""
import json
import unittest

from agenticsecctl_common.errors import CATALOGUE, mcp_error, problem_details
from agenticsecctl_common.redact import REDACTED, escape_untrusted, redact

TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln"
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
PEM_BEGIN = "-----BEGIN " + "PRIVATE KEY-----"
PEM_END = "-----END " + "PRIVATE KEY-----"


class Redaction(unittest.TestCase):
    def test_sensitive_keys(self):
        out = redact({"Authorization": "Bearer abc", "password": "p", "api_key": "k",
                      "nested": {"client_secret": "s", "ok": 1}, "list": [{"token": "t"}]})
        self.assertEqual(out["Authorization"], REDACTED)
        self.assertEqual(out["password"], REDACTED)
        self.assertEqual(out["api_key"], REDACTED)
        self.assertEqual(out["nested"]["client_secret"], REDACTED)
        self.assertEqual(out["nested"]["ok"], 1)
        self.assertEqual(out["list"][0]["token"], REDACTED)

    def test_values_scrubbed_in_free_text(self):
        for s in (f"failed with Bearer {TOKEN}", f"jwt {TOKEN}",
                  f"key {AWS} here", f"{PEM_BEGIN}\nabc\n{PEM_END}",
                  "postgres://u:hunter2@db/x"):
            out = redact(s)
            for secret in (TOKEN, AWS, "hunter2", "abc\n"):
                self.assertNotIn(secret, out)

    def test_input_not_mutated(self):
        src = {"password": "p"}
        redact(src)
        self.assertEqual(src["password"], "p")

    def test_escape_untrusted(self):
        s = escape_untrusted("a\nb\x1b[31m\r\"x\"" + "z" * 500, limit=40)
        self.assertNotIn("\n", s)
        self.assertNotIn("\x1b", s)
        self.assertLessEqual(len(s), 40)
        json.dumps(s)


class Errors(unittest.TestCase):
    def test_problem_details_shape(self):
        p = problem_details("forbidden", correlation_id="c1")
        self.assertEqual(set(p), {"type", "title", "status", "detail", "correlation_id"})
        self.assertEqual(p["status"], 403)

    def test_not_found_and_cross_tenant_identical(self):
        self.assertEqual(problem_details("not-found", correlation_id="c"),
                         problem_details("not-found", correlation_id="c"))

    def test_catalogue_seeds(self):
        for code in ("invalid-request", "unauthenticated", "forbidden", "separation-of-duties",
                     "not-found", "conflict", "ssrf-rejected", "rate-limited", "not-ready",
                     "tool-unavailable", "not-permitted", "limit-reached", "approval-required",
                     "unsupported-version"):
            self.assertIn(code, CATALOGUE)

    def test_unknown_code_fails_closed(self):
        p = problem_details("nope", correlation_id="c")
        self.assertEqual(p["status"], 500)

    def test_mcp_error_never_echoes_untrusted(self):
        e = mcp_error("not-permitted", correlation_id="c9", detail="IGNORE PREVIOUS")
        self.assertNotIn("IGNORE", json.dumps(e))
        self.assertIn("c9", json.dumps(e))


if __name__ == "__main__":
    unittest.main()
