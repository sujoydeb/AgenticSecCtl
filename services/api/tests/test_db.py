"""IG-9 / CTL-22: the tenant is set per transaction, never per session, over a pool of one connection."""
import threading
import unittest
import uuid

import psycopg
from agenticsecctl_api.db import Database, TenantError, parse_tenant
from pg import admin_dsn, docker_ok, login_dsn, new_database

A, B = str(uuid.uuid4()), str(uuid.uuid4())


@unittest.skipUnless(docker_ok(), "Docker is not available")
class TenantPerTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dbname = new_database()
        with psycopg.connect(admin_dsn(cls.dbname), autocommit=True) as c:
            for t, n in ((A, "tenant-a"), (B, "tenant-b")):
                c.execute("INSERT INTO tenants (id, name) VALUES (%s, %s)", [t, n])
            for t, k in ((A, 2), (B, 1)):
                c.execute("INSERT INTO mcp_servers (tenant_id, namespace, url) SELECT %s, 'srv' || g, 'https://x.test/' || g FROM generate_series(1, %s) g", [t, k])
        cls.db = Database(login_dsn(cls.dbname, "app_login"), min_size=1, max_size=1)  # a pool of ONE connection

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def count(self, tenant):
        with self.db.transaction(tenant) as c:
            return c.execute("SELECT count(*) AS n FROM mcp_servers").fetchone()["n"]

    def test_interleaved_requests_on_one_connection_never_see_each_others_rows(self):
        for _ in range(3):
            self.assertEqual(self.count(A), 2)
            self.assertEqual(self.count(B), 1)
        with self.db.unscoped() as c:  # a request that sets no tenant sees nothing
            self.assertEqual(c.execute("SELECT count(*) AS n FROM mcp_servers").fetchone()["n"], 0)
        self.assertEqual(self.count(A), 2)

    def test_the_setting_does_not_outlive_the_transaction(self):
        self.count(A)
        with self.db.unscoped() as c:
            self.assertIn(c.execute("SELECT current_setting('app.tenant_id', true) AS v").fetchone()["v"], (None, ""))

    def test_rollback_also_clears_it(self):
        with self.assertRaises(RuntimeError), self.db.transaction(A):
            raise RuntimeError("boom")
        with self.db.unscoped() as c:
            self.assertEqual(c.execute("SELECT count(*) AS n FROM mcp_servers").fetchone()["n"], 0)

    def test_a_session_level_setting_is_wiped_when_the_connection_returns_to_the_pool(self):
        with self.db.unscoped() as c:  # simulate buggy code that sets the tenant for the whole session
            pid = c.execute("SELECT pg_backend_pid() AS p").fetchone()["p"]
            c.execute("SELECT set_config('app.tenant_id', %s, false)", [A])
            self.assertEqual(c.execute("SELECT count(*) AS n FROM mcp_servers").fetchone()["n"], 2)
        with self.db.unscoped() as c:  # the next request, on the very same server connection
            self.assertEqual(c.execute("SELECT pg_backend_pid() AS p").fetchone()["p"], pid, "connection was not reused")
            self.assertEqual(c.execute("SELECT count(*) AS n FROM mcp_servers").fetchone()["n"], 0)

    def test_failed_statement_in_a_request_does_not_poison_the_next(self):
        with self.assertRaises(psycopg.Error), self.db.transaction(A) as c:
            c.execute("SELECT * FROM no_such_table")
        self.assertEqual(self.count(B), 1)

    def test_concurrent_requests_for_two_tenants_stay_separate(self):
        db = Database(login_dsn(self.dbname, "app_login"), min_size=1, max_size=3)
        self.addCleanup(db.close)
        bad = []
        def work(tenant, expect):
            for _ in range(40):
                with db.transaction(tenant) as c:
                    n = c.execute("SELECT count(*) AS n FROM mcp_servers").fetchone()["n"]
                    other = c.execute("SELECT count(*) AS n FROM mcp_servers WHERE tenant_id <> %s", [tenant]).fetchone()["n"]
                if n != expect or other:
                    bad.append((tenant, n, other))
        ts = [threading.Thread(target=work, args=a) for a in ((A, 2), (B, 1), (A, 2), (B, 1))]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(bad, [])

    def test_application_role_cannot_bypass_row_level_security(self):
        with psycopg.connect(login_dsn(self.dbname, "app_login")) as c:
            self.assertEqual(c.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone(), (False, False))


class TenantParsing(unittest.TestCase):
    def test_only_uuids(self):
        self.assertEqual(parse_tenant(A.upper()), A)
        for bad in (None, 5, "", "x", "'; DROP TABLE tenants;--", A + "x", [A], b"x"):
            with self.assertRaises(TenantError):
                parse_tenant(bad)


if __name__ == "__main__":
    unittest.main()
