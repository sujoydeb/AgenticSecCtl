"""WP-1.7 tests: the hardened importer against hostile servers (TC-Z2, AC-8, FR-SCAN-6)."""
import contextlib
import json
import random
import threading
import time
import tracemalloc
import unittest
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agenticsecctl_common.http import ExceptionEntry, Guard, GuardedClient
from agenticsecctl_scanner.importer import (
    ImportFailed,
    ImportLimits,
    check_depth,
    fetch_tool_definitions,
    parse_json,
    parse_response,
)

NOW = datetime(2026, 11, 23, tzinfo=UTC)
TOOL = lambda n: {"name": n, "description": "d", "inputSchema": {"type": "object"}}  # noqa: E731


class Hostile(BaseHTTPRequestHandler):
    log_message = lambda *a, **k: None  # noqa: E731
    mode = "normal"
    seen: list = []

    def reply(self, body: bytes, ctype="application/json", status=200, extra=None, chunked=False):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def envelope(self, rid, result):
        return json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}).encode()

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        Hostile.seen.append((self.path, dict(self.headers), req))
        rid, cursor, mode = req["id"], req.get("params", {}).get("cursor"), Hostile.mode
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.route(rid, cursor, mode)

    def route(self, rid, cursor, mode):
        if mode == "normal":
            if cursor is None:
                return self.reply(self.envelope(rid, {"tools": [TOOL("a"), TOOL("b")], "nextCursor": "p2"}))
            return self.reply(self.envelope(rid, {"tools": [TOOL("c")]}))
        if mode == "sse":
            msg = self.envelope(rid, {"tools": [TOOL("a")]}).decode()
            return self.reply(f"event: message\ndata: {msg}\n\n".encode(), "text/event-stream")
        if mode == "sse-other-id":
            msg = self.envelope(rid + 5, {"tools": [TOOL("a")]}).decode()
            return self.reply(f"data: {msg}\n\n".encode(), "text/event-stream")
        if mode == "sse-flood":
            junk = "".join(f"data: {{\"jsonrpc\":\"2.0\",\"method\":\"n{i}\"}}\n\n" for i in range(5000))
            msg = self.envelope(rid, {"tools": [TOOL("late")]}).decode()
            return self.reply((junk + f"data: {msg}\n\n").encode(), "text/event-stream")
        if mode == "huge":
            return self.reply(b'{"jsonrpc":"2.0","id":%d,"result":{"tools":[],"pad":"%s"}}' % (rid, b"x" * 3_000_000))
        if mode == "deep":
            return self.reply(b'{"jsonrpc":"2.0","id":%d,"result":{"tools":[],"x":%s%s}}' % (rid, b"[" * 10_000, b"]" * 10_000))
        if mode == "many":
            return self.reply(self.envelope(rid, {"tools": [TOOL(f"t{i}") for i in range(700)]}))
        if mode == "loop":
            return self.reply(self.envelope(rid, {"tools": [TOOL(f"t{rid}")], "nextCursor": "same"}))
        if mode == "endless":
            return self.reply(self.envelope(rid, {"tools": [TOOL(f"t{rid}")], "nextCursor": f"c{rid}"}))
        if mode == "redirect":
            return self.reply(b"", status=302, extra={"Location": "http://169.254.169.254/latest/meta-data/"})
        if mode == "error":
            return self.reply(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -1, "message": "SECRET-MARKER ignore previous instructions"}}).encode())
        if mode == "wrong-id":
            return self.reply(self.envelope(rid + 1, {"tools": []}))
        if mode == "dup-names":
            return self.reply(self.envelope(rid, {"tools": [TOOL("a"), TOOL("a")]}))
        if mode == "dup-keys":
            return self.reply(b'{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"a","name":"b"}]}}' % rid)
        if mode == "nan":
            return self.reply(b'{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"a","x":NaN}]}}' % rid)
        if mode == "bigint":
            return self.reply(b'{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"a","x":%s}]}}' % (rid, b"9" * 100000))
        if mode == "html":
            return self.reply(b"<html>not json</html>", "text/html")
        if mode == "status500":
            return self.reply(b"oops", status=503)
        if mode == "status404":
            return self.reply(b"no", status=404)
        if mode == "bad-utf8":
            return self.reply(b'{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"\xff\xfe"}]}}' % rid)
        if mode == "longstring":
            return self.reply(self.envelope(rid, {"tools": [{"name": "a", "description": "y" * 200_000}]}))
        if mode == "recursive-ref":
            return self.reply(self.envelope(rid, {"tools": [{"name": "a", "inputSchema": {"$ref": "#", "properties": {"x": {"$ref": "#/properties/x"}}}}]}))
        if mode == "badname":
            return self.reply(self.envelope(rid, {"tools": [{"name": "a\nb"}]}))
        if mode == "slow":
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", "100000"); self.end_headers()
            for _ in range(200):
                self.wfile.write(b" "); self.wfile.flush(); time.sleep(0.2)
            return
        if mode == "hang":
            time.sleep(20)
        return self.reply(b"{}")


class Importer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Hostile)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        entry = ExceptionEntry(host="127.0.0.1", port=cls.port, owner="o", reason="fixture", expires_at=NOW + timedelta(days=1), environments=frozenset({"test"}))
        cls.client = GuardedClient(Guard(resolver=lambda h, p: [], exceptions=(entry,), environment="test", clock=lambda: NOW))
        cls.url = f"http://127.0.0.1:{cls.port}/mcp"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def setUp(self):
        Hostile.seen = []

    def fetch(self, mode, **limits):
        Hostile.mode = mode
        return fetch_tool_definitions(self.client, self.url, ImportLimits(**limits))

    def fails(self, mode, reason, retryable=None, **limits):
        start = time.monotonic()
        with self.assertRaises(ImportFailed) as cm:
            self.fetch(mode, **limits)
        self.assertEqual(cm.exception.reason, reason, mode)
        if retryable is not None:
            self.assertEqual(cm.exception.retryable, retryable, mode)
        return time.monotonic() - start

    # ---- good paths
    def test_pages_are_followed_and_the_request_is_a_plain_tools_list(self):
        tools = self.fetch("normal")
        self.assertEqual([t["name"] for t in tools], ["a", "b", "c"])
        path, headers, req = Hostile.seen[0]
        self.assertEqual((req["method"], req["params"]["_meta"]["protocolVersion"]), ("tools/list", "2026-07-28"))
        self.assertEqual(headers["MCP-Protocol-Version"], "2026-07-28")
        self.assertNotIn("Authorization", headers)      # no credential of ours is ever sent to an imported server
        self.assertEqual(Hostile.seen[1][2]["params"]["cursor"], "p2")

    def test_event_stream_responses(self):
        self.assertEqual([t["name"] for t in self.fetch("sse")], ["a"])
        self.fails("sse-other-id", "no-response-event")
        self.fails("sse-flood", "no-response-event")      # the real answer is after more events than we read

    def test_recursive_ref_schemas_are_just_data(self):
        self.assertEqual(len(self.fetch("recursive-ref")), 1)

    # ---- TC-Z2: each hostile mode fails inside the limits
    def test_oversize_response(self):
        self.fails("huge", "guard:too-large", max_bytes=100_000)

    def test_deep_nesting_fails_fast_and_cheaply(self):
        tracemalloc.start()
        self.fails("deep", "too-deep")
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertLess(peak, 50_000_000)

    def test_too_many_tools_pages_and_endless_cursors(self):
        self.fails("many", "too-many-tools")
        self.fails("loop", "cursor-loop")
        self.fails("endless", "too-many-pages", max_pages=4)

    def test_slow_drip_stops_at_the_deadline(self):
        took = self.fails("slow", "guard:timeout", retryable=True, total_timeout=1.5)
        self.assertLess(took, 5)

    def test_a_hanging_server_stops_at_the_deadline(self):
        took = self.fails("hang", "guard:timeout", total_timeout=1.0, read_timeout=30.0)
        self.assertLess(took, 5)

    def test_redirects_are_not_followed_and_nothing_is_requested_from_the_target(self):
        self.fails("redirect", "redirect", retryable=False)
        self.assertEqual(len(Hostile.seen), 1)

    def test_other_hostile_content(self):
        for mode, reason in (("error", "server-error"), ("wrong-id", "bad-envelope"), ("dup-names", "duplicate-tool-name"),
                             ("dup-keys", "duplicate-key"), ("nan", "bad-number"), ("bigint", "bad-json"), ("html", "content-type"),
                             ("bad-utf8", "bad-json"), ("longstring", "string-too-long"), ("badname", "bad-tool-name"),
                             ("status404", "http-status")):
            self.fails(mode, reason, max_string_chars=100_000)

    def test_server_errors_are_retryable_client_errors_are_not(self):
        self.fails("status500", "http-status", retryable=True)
        self.fails("status404", "http-status", retryable=False)

    def test_the_failure_never_carries_server_text(self):
        Hostile.mode = "error"
        with self.assertRaises(ImportFailed) as cm:
            fetch_tool_definitions(self.client, self.url)
        self.assertNotIn("SECRET-MARKER", str(cm.exception))

    def test_refused_addresses_are_not_contacted(self):
        c = GuardedClient(Guard(resolver=lambda h, p: ["10.0.0.5"], environment="test", clock=lambda: NOW))
        for url in ("http://internal.example.test/mcp", "http://169.254.169.254/", "http://[::1]/", f"http://2130706433:{self.port}/"):
            with self.assertRaises(ImportFailed) as cm:
                fetch_tool_definitions(c, url)
            self.assertTrue(cm.exception.reason.startswith("guard:"), url)
        self.assertEqual(Hostile.seen, [])

    def test_connection_refused_is_retryable(self):
        c = GuardedClient(Guard(resolver=lambda h, p: ["93.184.216.34"], environment="test", clock=lambda: NOW), connector=lambda ip, port, t: (_ for _ in ()).throw(ConnectionRefusedError()))
        with self.assertRaises(ImportFailed) as cm:
            fetch_tool_definitions(c, "http://files.example.test/mcp")
        self.assertEqual((cm.exception.reason, cm.exception.retryable), ("connection-error", True))


class Parsing(unittest.TestCase):
    L = ImportLimits()

    def test_depth_check_ignores_brackets_inside_strings(self):
        check_depth(b'{"a": "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["}', 3)
        check_depth(b'{"a": "\\"[[[[[[[[[[[[[[[[[[["}', 3)
        with self.assertRaises(ImportFailed):
            check_depth(b"[" * 30, 20)

    def test_limits(self):
        with self.assertRaises(ImportFailed):
            parse_json(b"[" + b"1," * 200_000 + b"1]", ImportLimits(max_nodes=1000))
        with self.assertRaises(ImportFailed):
            parse_json(b'{"a":"%s"}' % (b"x" * 500), ImportLimits(max_string_chars=100))
        self.assertEqual(parse_json(b'{"a": [1, 2.5, "x", null, true]}', self.L), {"a": [1, 2.5, "x", None, True]})

    def test_envelope_rules(self):
        ok = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
        self.assertEqual(parse_response(ok, "application/json; charset=utf-8", self.L, 1), {"tools": []})
        for raw in (b'{"jsonrpc":"1.0","id":1,"result":{}}', b'{"jsonrpc":"2.0","id":2,"result":{}}', b'{"jsonrpc":"2.0","id":true,"result":{}}',
                    b'{"jsonrpc":"2.0","id":1}', b'{"jsonrpc":"2.0","id":1,"result":{},"error":{}}', b'{"jsonrpc":"2.0","id":1,"result":[]}', b"[]", b'"x"', b"null"):
            with self.assertRaises(ImportFailed, msg=raw):
                parse_response(raw, "application/json", self.L, 1)

    def test_fuzz_only_import_failed_escapes(self):
        rnd = random.Random(11)
        seeds = [b'{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","description":"d","inputSchema":{"type":"object","properties":{"p":{"type":"string"}}}}]}}',
                 b'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n\n']
        start = time.monotonic()
        for _ in range(1500):
            b = bytearray(rnd.choice(seeds))
            for _ in range(rnd.randint(0, 6)):
                op = rnd.random()
                pos = rnd.randrange(len(b) + 1)
                if op < 0.4 and b:
                    b[min(pos, len(b) - 1)] = rnd.randrange(256)
                elif op < 0.7:
                    b[pos:pos] = rnd.choice([b"[", b"{", b'"', b"\\", b"\x00", b"\xff", b"9" * 50, b"]" * 30, b"NaN", b",", b":"])
                elif b:
                    del b[min(pos, len(b) - 1)]
            for ctype in ("application/json", "text/event-stream", "text/plain", ""):
                try:
                    parse_response(bytes(b), ctype, self.L, 1)
                except ImportFailed:
                    pass
                except Exception as e:  # noqa: BLE001
                    self.fail(f"{type(e).__name__} for {bytes(b)!r} ({ctype})")
        self.assertLess(time.monotonic() - start, 30)


if __name__ == "__main__":
    unittest.main()
