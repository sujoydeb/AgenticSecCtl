"""WP-1.7 / TC-Z2: the guarded client enforces a wall-clock limit, not only per-read timeouts."""
import socket
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta

from agenticsecctl_common.http import ExceptionEntry, Guard, GuardedClient, SsrfRejected

NOW = datetime(2026, 11, 23, tzinfo=UTC)


class Drip(threading.Thread):
    """A raw TCP server: mode 'body' drips the body, 'headers' drips the header, 'silent' never answers."""

    def __init__(self, mode):
        super().__init__(daemon=True)
        self.mode = mode
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        try:
            c.settimeout(5)
            c.recv(4096)
            if self.mode == "silent":
                time.sleep(30)
                return
            if self.mode == "close-drip":  # HTTP/1.0 style: the connection ends the body, http.client drops its socket reference
                c.sendall(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n")
                for _ in range(1000):
                    c.sendall(b"x"); time.sleep(0.2)
                return
            if self.mode == "garbage":
                c.sendall(b"this is not http\r\n\r\n")
                return
            if self.mode == "short":
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
                return
            if self.mode == "headers":
                for ch in b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Slow: " + b"a" * 200:
                    c.sendall(bytes([ch])); time.sleep(0.2)
                return
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            for _ in range(1000):
                c.sendall(b"x"); time.sleep(0.2)
        except OSError:
            pass
        finally:
            c.close()


class Deadline(unittest.TestCase):
    def client(self, port):
        entry = ExceptionEntry(host="127.0.0.1", port=port, owner="o", reason="test", expires_at=NOW + timedelta(days=1), environments=frozenset({"test"}))
        return GuardedClient(Guard(resolver=lambda h, p: [], exceptions=(entry,), environment="test", clock=lambda: NOW))

    def run_mode(self, mode, total, per_read=10.0):
        srv = Drip(mode); srv.start()
        self.addCleanup(lambda: (setattr(srv, "stop", True), srv.srv.close()))
        t = time.monotonic()
        with self.assertRaises(SsrfRejected) as cm:
            self.client(srv.port).request("GET", f"http://127.0.0.1:{srv.port}/", timeout=per_read, total_timeout=total)
        return cm.exception.reason, time.monotonic() - t

    def test_slow_drip_body_stops_at_the_deadline(self):
        reason, took = self.run_mode("body", 1.5)
        self.assertEqual(reason, "timeout")
        self.assertLess(took, 4)

    def test_slow_drip_on_a_connection_closing_response_stops_at_the_deadline(self):
        reason, took = self.run_mode("close-drip", 1.5)
        self.assertEqual(reason, "timeout")
        self.assertLess(took, 4)

    def test_slow_drip_headers_stop_at_the_deadline(self):
        reason, took = self.run_mode("headers", 1.5)
        self.assertEqual(reason, "timeout")
        self.assertLess(took, 4)

    def test_a_silent_server_stops_at_the_deadline_even_with_a_long_read_timeout(self):
        reason, took = self.run_mode("silent", 1.0, per_read=20.0)
        self.assertEqual(reason, "timeout")
        self.assertLess(took, 4)

    def test_without_a_deadline_behaviour_is_unchanged(self):
        srv = Drip("silent"); srv.start()
        self.addCleanup(lambda: (setattr(srv, "stop", True), srv.srv.close()))
        with self.assertRaises(Exception) as cm:  # the per-read timeout still applies
            self.client(srv.port).request("GET", f"http://127.0.0.1:{srv.port}/", timeout=0.5)
        self.assertNotIsInstance(cm.exception, SsrfRejected)

    def test_a_body_shorter_than_its_content_length_is_a_failure_not_a_result(self):
        srv = Drip("short"); srv.start()
        self.addCleanup(lambda: (setattr(srv, "stop", True), srv.srv.close()))
        with self.assertRaises(SsrfRejected) as cm:
            self.client(srv.port).request("GET", f"http://127.0.0.1:{srv.port}/")
        self.assertEqual(cm.exception.reason, "incomplete-body")

    def test_a_peer_that_does_not_speak_http_is_a_stable_reason(self):
        srv = Drip("garbage"); srv.start()
        self.addCleanup(lambda: (setattr(srv, "stop", True), srv.srv.close()))
        with self.assertRaises(SsrfRejected) as cm:
            self.client(srv.port).request("GET", f"http://127.0.0.1:{srv.port}/")
        self.assertEqual(cm.exception.reason, "protocol-error")

    def test_bad_deadline_values_are_refused(self):
        for bad in (0, -1, float("nan")):
            with self.assertRaises(ValueError):
                self.client(1).request("GET", "http://127.0.0.1:1/", total_timeout=bad)


if __name__ == "__main__":
    unittest.main()
