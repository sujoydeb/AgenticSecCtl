"""WP-1.3 tests: SSRF guard (TC-H1..H4, FR-SSRF-1..5)."""
import http.server
import threading
import unittest
from datetime import UTC, datetime, timedelta

from agenticsecctl_common.http import ExceptionEntry, Guard, GuardedClient, SsrfRejected, validate_url

PUBLIC = "93.184.216.34"
NOW = datetime(2026, 11, 22, tzinfo=UTC)


def resolver_for(mapping):
    def r(host, port):
        if host in mapping:
            return list(mapping[host])
        raise OSError("nxdomain")
    return r


def guard(mapping=None, entries=(), env="development"):
    return Guard(resolver=resolver_for(mapping or {"example.com": [PUBLIC]}),
                 exceptions=tuple(entries), environment=env, clock=lambda: NOW)


HOSTILE = [
    # TC-H1: metadata and private ranges
    "http://169.254.169.254/latest/meta-data", "http://127.0.0.1/", "http://10.0.0.1/",
    "http://192.168.1.1/", "http://172.16.0.1/", "http://100.64.0.1/", "http://0.0.0.0/",
    "http://224.0.0.1/", "http://[::1]/", "http://[fe80::1]/", "http://[fd00::1]/",
    "http://localhost/", "http://LOCALHOST./", "http://foo.localhost/",
    "http://metadata.google.internal/", "http://instance-data/",
    # TC-H4: alternate encodings
    "http://2130706433/", "http://0x7f000001/", "http://017700000001/", "http://127.1/",
    "http://0/", "http://0177.0.0.1/", "http://0x7f.0.0.1/", "http://2852039166/",
    "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/", "http://[::ffff:169.254.169.254]/",
    "http://[64:ff9b::7f00:1]/", "http://[2002:7f00:1::]/", "http://[::127.0.0.1]/",
    "http://[fe80::1%25eth0]/", "http://1.1.1.1.1/", "http://127。0。0。1/",
    "http://①②⑦.0.0.1/",
    # userinfo and parser tricks
    "http://example.com@127.0.0.1/", "http://127.0.0.1#@example.com/",
    "http://example.com\\@127.0.0.1/", "http://127.0.0.1%2f@example.com/",
    "http://exa mple.com/", "http://example.com\n.evil/",
    # schemes
    "ftp://example.com/", "file:///etc/passwd", "gopher://example.com/", "//example.com/", "example.com",
]


class Hostile(unittest.TestCase):
    def test_table_rejected(self):
        g = guard({"example.com": [PUBLIC], "foo.localhost": ["127.0.0.1"]})
        for url in HOSTILE:
            with self.subTest(url=url), self.assertRaises(SsrfRejected):
                validate_url(url, g)

    def test_public_allowed(self):
        for url, ip in (("https://example.com/a?b=1", PUBLIC), (f"http://{PUBLIC}:8080/", PUBLIC)):
            t = validate_url(url, guard())
            self.assertEqual(t.ips[0], ip)

    def test_default_ports(self):
        self.assertEqual(validate_url("https://example.com/", guard()).port, 443)
        self.assertEqual(validate_url("http://example.com/", guard()).port, 80)

    def test_any_bad_answer_rejects(self):
        g = guard({"example.com": [PUBLIC, "10.0.0.5"]})
        with self.assertRaises(SsrfRejected):
            validate_url("https://example.com/", g)

    def test_resolution_failure_rejected(self):
        with self.assertRaises(SsrfRejected):
            validate_url("https://nope.example/", guard())


class Exceptions(unittest.TestCase):
    def entry(self, **kw):
        base = {"host": "keycloak.dev", "port": 8080, "owner": "security-engineer",
                "reason": "development identity provider",
                "expires_at": NOW + timedelta(days=30), "environments": frozenset({"development"})}
        base.update(kw)
        return ExceptionEntry(**base)

    M = {"keycloak.dev": ["10.1.2.3"]}

    def test_refused_without_entry(self):
        with self.assertRaises(SsrfRejected):
            validate_url("http://keycloak.dev:8080/realms/x", guard(self.M))

    def test_allowed_with_entry(self):
        t = validate_url("http://keycloak.dev:8080/realms/x", guard(self.M, [self.entry()]))
        self.assertEqual(t.ips, ("10.1.2.3",))

    def test_scoped_to_port_and_host(self):
        g = guard({**self.M, "other.dev": ["10.1.2.4"]}, [self.entry()])
        for url in ("http://keycloak.dev:9090/", "http://other.dev:8080/"):
            with self.assertRaises(SsrfRejected):
                validate_url(url, g)

    def test_refused_after_expiry(self):
        g = Guard(resolver=resolver_for(self.M), exceptions=(self.entry(),), environment="development",
                  clock=lambda: NOW + timedelta(days=31))
        with self.assertRaises(SsrfRejected) as cm:
            validate_url("http://keycloak.dev:8080/", g)
        self.assertEqual(cm.exception.reason, "blocked-address")

    def test_wrong_environment(self):
        with self.assertRaises(SsrfRejected):
            validate_url("http://keycloak.dev:8080/", guard(self.M, [self.entry()], env="production"))

    def test_entry_needs_owner_reason_expiry(self):
        for bad in ({"owner": ""}, {"reason": " "}, {"expires_at": None},
                    {"expires_at": datetime(2027, 1, 1)}):  # naive time
            with self.assertRaises(ValueError):
                self.entry(**bad)

    def test_userinfo_still_refused_with_entry(self):
        with self.assertRaises(SsrfRejected):
            validate_url("http://u@keycloak.dev:8080/", guard(self.M, [self.entry()]))


class Pinning(unittest.TestCase):
    def test_connects_to_validated_ip_resolved_once(self):
        calls, connected = [], []
        answers = iter([[PUBLIC], ["127.0.0.1"]])  # rebinding: second answer is internal

        def res(host, port):
            calls.append(host)
            return next(answers)

        def connector(ip, port, timeout):
            connected.append(ip)
            raise ConnectionRefusedError

        c = GuardedClient(Guard(resolver=res, clock=lambda: NOW), connector=connector)
        with self.assertRaises(ConnectionRefusedError):
            c.request("GET", "http://rebind.example/")
        self.assertEqual(calls, ["rebind.example"])
        self.assertEqual(connected, [PUBLIC])


class _H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/ok":
            body = b"hello"
            self.send_response(200)
        elif self.path == "/big":
            body = b"x" * 5000
            self.send_response(200)
        elif self.path.startswith("/hop"):
            n = int(self.path[4:] or 0)
            self.send_response(302)
            self.send_header("Location", f"/hop{n + 1}" if n < 10 else "/ok")
            body = b""
        elif self.path == "/internal":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data")
            body = b""
        elif self.path == "/rel":
            self.send_response(302)
            self.send_header("Location", "/ok")
            body = b""
        else:
            self.send_response(404)
            body = b""
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Client(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        entry = ExceptionEntry(host="127.0.0.1", port=cls.port, owner="o", reason="test fixture",
                               expires_at=NOW + timedelta(days=1), environments=frozenset({"test"}))
        cls.client = GuardedClient(Guard(resolver=resolver_for({}), exceptions=(entry,),
                                         environment="test", clock=lambda: NOW))
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_get(self):
        r = self.client.request("GET", self.base + "/ok")
        self.assertEqual((r.status, r.body), (200, b"hello"))

    def test_redirect_off_by_default_returned_not_followed(self):
        r = self.client.request("GET", self.base + "/rel")
        self.assertEqual(r.status, 302)

    def test_redirect_followed_when_enabled(self):
        r = self.client.request("GET", self.base + "/rel", follow_redirects=True)
        self.assertEqual(r.body, b"hello")

    def test_redirect_to_metadata_rejected(self):
        with self.assertRaises(SsrfRejected) as cm:
            self.client.request("GET", self.base + "/internal", follow_redirects=True)
        self.assertEqual(cm.exception.reason, "blocked-address")

    def test_redirect_limit(self):
        with self.assertRaises(SsrfRejected) as cm:
            self.client.request("GET", self.base + "/hop0", follow_redirects=True)
        self.assertEqual(cm.exception.reason, "redirect-limit")

    def test_size_limit_is_an_error(self):
        with self.assertRaises(SsrfRejected) as cm:
            self.client.request("GET", self.base + "/big", max_bytes=1000)
        self.assertEqual(cm.exception.reason, "too-large")

    def test_unexcepted_loopback_refused(self):
        c = GuardedClient(Guard(resolver=resolver_for({}), environment="test", clock=lambda: NOW))
        with self.assertRaises(SsrfRejected):
            c.request("GET", self.base + "/ok")


if __name__ == "__main__":
    unittest.main()
