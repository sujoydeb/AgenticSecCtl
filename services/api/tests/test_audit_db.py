"""WP-1.4 and WP-1.6: the audit chain in PostgreSQL (TC-Z6 database-backed run, FR-AUD-1/2, CTL-13)."""
import threading
import unittest

import psycopg
from agenticsecctl_api import audit, events
from agenticsecctl_api import registry as r
from pg import docker_ok, login_dsn
from world import GUARD, Env


@unittest.skipUnless(docker_ok(), "Docker is not available")
class AuditChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()

    @classmethod
    def tearDownClass(cls):
        cls.env.close()

    def setUp(self):
        self.t = self.env.tenant()

    def activity(self, n=3):
        """Real registry activity: produces approval.requested, server.registered, tool events..."""
        alice, eve, amir = self.t.actor("alice"), self.t.actor("eve"), self.t.actor("amir")
        with self.env.app.transaction(self.t.id) as c:
            s = r.register_server(c, alice, namespace="files", url="https://files.example.test/mcp", guard=GUARD)
            tools = [{"name": f"t{i}", "description": "d"} for i in range(n)]
            out = r.submit_definitions(c, eve, s["id"], tools)
        with self.env.app.transaction(self.t.id) as c:
            r.decide_approval(c, amir, out[0]["approval_id"], decision="approve", action_class="read", key="k")

    def chain(self):
        with self.env.app.transaction(self.t.id) as c:
            return audit.rows(c, self.t.id)

    def test_outbox_becomes_a_verified_chain(self):
        self.activity()
        with self.env.admin() as c:
            pending = c.execute("SELECT count(*) FROM outbox WHERE tenant_id = %s AND state = 'pending'", [self.t.id]).fetchone()[0]
        self.assertGreaterEqual(pending, 6)
        self.assertEqual(audit.drain(self.env.audit, self.t.id), pending)
        self.assertEqual(audit.drain(self.env.audit, self.t.id), 0)
        rows = self.chain()
        self.assertEqual([x["seq"] for x in rows], list(range(1, pending + 1)))
        with self.env.app.transaction(self.t.id) as c:
            v = audit.verify(c, self.t.id)
        self.assertTrue(v.ok, v)
        self.assertEqual(v.checked, pending)
        with self.env.admin() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM outbox WHERE tenant_id = %s AND state = 'pending'", [self.t.id]).fetchone()[0], 0)

    def test_the_chain_continues_across_batches(self):
        self.activity(1)
        audit.drain(self.env.audit, self.t.id, batch=2)
        with self.env.app.transaction(self.t.id) as c:
            events.emit(c, self.t.id, "config.changed", "user:x")
        while audit.drain(self.env.audit, self.t.id, batch=2):
            pass
        with self.env.app.transaction(self.t.id) as c:
            self.assertTrue(audit.verify(c, self.t.id).ok)
            self.assertEqual([x["seq"] for x in audit.rows(c, self.t.id)][-1], len(self.chain()))

    def test_tamper_detection_on_the_stored_table(self):
        self.activity(); audit.drain(self.env.audit, self.t.id)
        n = len(self.chain())
        def verify():
            with self.env.app.transaction(self.t.id) as c:
                return audit.verify(c, self.t.id)
        with self.env.admin() as c:  # a privileged actor switches the immutability trigger off
            c.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
            try:
                c.execute("UPDATE audit_events SET actor = 'user:mallory' WHERE tenant_id = %s AND seq = 3", [self.t.id])
                v = verify()
                self.assertEqual((v.ok, v.first_bad_seq, v.kind), (False, 3, "modified"))
                c.execute("DELETE FROM audit_events WHERE tenant_id = %s AND seq = 4", [self.t.id])
                v = verify()
                self.assertEqual((v.ok, v.first_bad_seq), (False, 3))  # row 3 is still altered: the first bad row is reported
                c.execute("DELETE FROM audit_events WHERE tenant_id = %s AND seq = 3", [self.t.id])
                v = verify()
                self.assertEqual((v.first_bad_seq, v.kind), (3, "deleted"))
            finally:
                c.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable")
        self.assertGreater(n, 4)

    def test_event_changes_are_visible_to_the_verifier_for_every_stored_field(self):
        self.activity(); audit.drain(self.env.audit, self.t.id)
        for column, value in (("event_type", "tool.rejected"), ("subject_id", "x"), ("decision", "deny"), ("redacted_excerpt", "edited"),
                              ("occurred_at", "2001-01-01T00:00:00Z")):
            with self.env.admin() as c:
                c.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable")
                try:
                    old = c.execute(f"SELECT {column} FROM audit_events WHERE tenant_id = %s AND seq = 1", [self.t.id]).fetchone()[0]  # noqa: S608
                    c.execute(f"UPDATE audit_events SET {column} = %s WHERE tenant_id = %s AND seq = 1", [value, self.t.id])  # noqa: S608
                    with self.env.app.transaction(self.t.id) as cc:
                        v = audit.verify(cc, self.t.id)
                    self.assertEqual((v.ok, v.first_bad_seq), (False, 1), column)
                    c.execute(f"UPDATE audit_events SET {column} = %s WHERE tenant_id = %s AND seq = 1", [old, self.t.id])  # noqa: S608
                finally:
                    c.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable")
        with self.env.app.transaction(self.t.id) as cc:
            self.assertTrue(audit.verify(cc, self.t.id).ok)

    def test_concurrent_drains_write_each_event_once_in_a_valid_chain(self):
        self.activity(8)
        errors = []
        def work():
            try:
                for _ in range(5):
                    audit.drain(self.env.audit, self.t.id, batch=3)
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        ts = [threading.Thread(target=work) for _ in range(4)]
        [t.start() for t in ts]; [t.join() for t in ts]
        while audit.drain(self.env.audit, self.t.id):
            pass
        self.assertEqual(errors, [])
        rows = self.chain()
        self.assertEqual([x["seq"] for x in rows], list(range(1, len(rows) + 1)))
        self.assertEqual(len({x["event_id"] for x in rows}), len(rows))
        with self.env.app.transaction(self.t.id) as c:
            self.assertTrue(audit.verify(c, self.t.id).ok)

    def test_tenants_have_separate_chains(self):
        self.activity(); other = self.env.tenant()
        with self.env.app.transaction(other.id) as c:
            events.emit(c, other.id, "config.changed", "user:o")
        audit.drain(self.env.audit, self.t.id); audit.drain(self.env.audit, other.id)
        with self.env.app.transaction(other.id) as c:
            rows = audit.rows(c, other.id)
            self.assertEqual([x["seq"] for x in rows], [1])
            self.assertTrue(audit.verify(c, other.id).ok)
        self.assertGreater(len(self.chain()), 1)

    def test_only_the_audit_writer_can_write_the_chain_and_the_application_only_reads(self):
        self.activity(1)
        with psycopg.connect(login_dsn(self.env.dbname, "app_login")) as c:
            c.execute("SELECT set_config('app.tenant_id', %s, false)", [self.t.id])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("INSERT INTO audit_events (tenant_id, seq, event_id, occurred_at, event_type, actor, prev_hash, hash) "
                          "VALUES (%s, 1, 'x', now(), 'a.b', 'x', %s, %s)", [self.t.id, bytes(32), bytes(32)])
        with psycopg.connect(login_dsn(self.env.dbname, "audit_login")) as c:
            c.execute("SELECT set_config('app.tenant_id', %s, false)", [self.t.id])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("UPDATE outbox SET event = '{}'")
            c.rollback()
            c.execute("SELECT set_config('app.tenant_id', %s, false)", [self.t.id])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                c.execute("SELECT * FROM agents")

    def test_event_text_is_redacted_and_validated(self):
        with self.env.app.transaction(self.t.id) as c:
            events.emit(c, self.t.id, "config.changed", "user:x", excerpt="token Bearer abc.def.ghi leaked\x1b[31m")
            with self.assertRaises(ValueError):
                events.emit(c, self.t.id, "not.in.vocabulary", "user:x")
        audit.drain(self.env.audit, self.t.id)
        ex = self.chain()[0]["redacted_excerpt"]
        self.assertNotIn("abc.def", ex)
        self.assertNotIn("\x1b", ex)


if __name__ == "__main__":
    unittest.main()
