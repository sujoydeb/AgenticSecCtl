"""PAR-O-27: the migration runner (up, down, checksums, atomicity, concurrency)."""
import tempfile
import threading
import unittest
from pathlib import Path

import psycopg
from pg import admin_dsn, docker_ok, ensure_logins, new_database

from agenticsecctl_api import migrate as m


def mdir(tmp, files):
    d = Path(tmp)
    for name, sql in files.items():
        (d / name).write_text(sql)
    return d


GOOD = {"0001_a.up.sql": "CREATE TABLE a (i int);", "0001_a.down.sql": "DROP TABLE a;",
        "0002_b.up.sql": "CREATE TABLE b (i int);", "0002_b.down.sql": "DROP TABLE b;"}


class Discovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)

    def test_good_set(self):
        ms = m.discover(mdir(self.tmp.name, GOOD))
        self.assertEqual([(x.version, x.name) for x in ms], [(1, "a"), (2, "b")])

    def test_rejects_bad_sets(self):
        for label, files in {
            "gap": {k: v for k, v in GOOD.items() if not k.startswith("0001")},
            "missing down": {k: v for k, v in GOOD.items() if k != "0002_b.down.sql"},
            "stray file": {**GOOD, "notes.sql": "x"},
            "name mismatch": {**GOOD, "0002_c.down.sql": "DROP TABLE b;", "0002_b.down.sql": None},
            "bad number": {"001_a.up.sql": "x", "001_a.down.sql": "x"},
        }.items():
            with tempfile.TemporaryDirectory() as t:
                d = mdir(t, {k: v for k, v in files.items() if v is not None})
                with self.assertRaises(m.MigrationError, msg=label):
                    m.discover(d)

    def test_product_migrations_are_well_formed(self):
        self.assertGreaterEqual(len(m.discover()), 1)


@unittest.skipUnless(docker_ok(), "Docker is not available")
class Runner(unittest.TestCase):
    def setUp(self):
        self.db = new_database(migrate=False)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)

    def conn(self):
        c = psycopg.connect(admin_dsn(self.db)); self.addCleanup(c.close); return c

    def tables(self, c):
        return sorted(r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))

    def test_up_is_idempotent_and_down_up_round_trips(self):
        ms = m.discover(mdir(self.tmp.name, GOOD)); c = self.conn()
        self.assertEqual(m.up(c, ms), [1, 2])
        self.assertEqual(m.up(c, ms), [])
        self.assertEqual(self.tables(c), ["a", "b", "schema_migrations"])
        self.assertEqual(m.down(c, ms), [2])
        self.assertEqual(self.tables(c), ["a", "schema_migrations"])
        self.assertEqual(m.down(c, ms, steps=5), [1])
        self.assertEqual(self.tables(c), ["schema_migrations"])
        self.assertEqual(m.down(c, ms), [])
        self.assertEqual(m.up(c, ms), [1, 2])
        self.assertEqual(m.status(c, ms), [(1, "a", "applied"), (2, "b", "applied")])

    def test_target_version(self):
        ms = m.discover(mdir(self.tmp.name, GOOD)); c = self.conn()
        self.assertEqual(m.up(c, ms, target=1), [1])
        self.assertEqual(m.status(c, ms), [(1, "a", "applied"), (2, "b", "pending")])

    def test_editing_an_applied_migration_is_refused(self):
        d = mdir(self.tmp.name, GOOD); c = self.conn()
        m.up(c, m.discover(d))
        (d / "0001_a.up.sql").write_text("CREATE TABLE a (i int, evil text);")
        for op in (lambda: m.up(c, m.discover(d)), lambda: m.down(c, m.discover(d)), lambda: m.status(c, m.discover(d))):
            with self.assertRaises(m.MigrationError) as cm:
                op()
            self.assertIn("edited", str(cm.exception))

    def test_database_ahead_of_checkout_is_refused(self):
        d = mdir(self.tmp.name, GOOD); c = self.conn()
        m.up(c, m.discover(d))
        for f in ("0002_b.up.sql", "0002_b.down.sql"):
            (d / f).unlink()
        with self.assertRaises(m.MigrationError):
            m.up(c, m.discover(d))

    def test_failing_migration_leaves_nothing_behind(self):
        files = {**GOOD, "0002_b.up.sql": "CREATE TABLE b (i int); CREATE TABLE a (i int);"}  # second statement fails
        ms = m.discover(mdir(self.tmp.name, files)); c = self.conn()
        with self.assertRaises(m.MigrationError) as cm:
            m.up(c, ms)
        self.assertIn("rolled back", str(cm.exception))
        self.assertEqual(self.tables(c), ["a", "schema_migrations"])  # 0001 stays, nothing of 0002
        self.assertEqual(m.status(c, ms), [(1, "a", "applied"), (2, "b", "pending")])

    def test_failing_rollback_is_undone(self):
        files = {**GOOD, "0002_b.down.sql": "DROP TABLE b; DROP TABLE nonexistent;"}
        ms = m.discover(mdir(self.tmp.name, files)); c = self.conn()
        m.up(c, ms)
        with self.assertRaises(m.MigrationError):
            m.down(c, ms)
        self.assertEqual(self.tables(c), ["a", "b", "schema_migrations"])
        self.assertEqual(m.status(c, ms)[1], (2, "b", "applied"))

    def test_concurrent_runners_apply_each_migration_once(self):
        ms = m.discover(mdir(self.tmp.name, GOOD)); results, errors = [], []
        def run():
            try:
                with psycopg.connect(admin_dsn(self.db)) as c:
                    results.append(m.up(c, ms))
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        ts = [threading.Thread(target=run) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(sorted(sum(results, [])), [1, 2])

    def test_command_line_reads_the_dsn_from_the_environment_only(self):
        import os
        old = dict(os.environ)
        try:
            os.environ.pop("AGENTIC_MIGRATE_DSN", None)
            self.assertEqual(m.main(["up"]), 2)
            os.environ.update({"AGENTIC_MIGRATE_DSN": admin_dsn(self.db), "AGENTIC_MIGRATIONS_DIR": mdir(self.tmp.name, GOOD).as_posix()})
            self.assertEqual(m.main(["up"]), 0)
            self.assertEqual(m.main(["down", "--steps", "1"]), 0)
            self.assertEqual(m.main(["status"]), 0)
            self.assertEqual(m.main(["bogus"]), 2)
        finally:
            os.environ.clear(); os.environ.update(old)


@unittest.skipUnless(docker_ok(), "Docker is not available")
class ProductMigrations(unittest.TestCase):
    def test_baseline_up_down_up_and_bookkeeping_is_private(self):
        db = new_database(migrate=False)
        ms = m.discover()
        with psycopg.connect(admin_dsn(db)) as c:
            self.assertEqual(m.up(c, ms), [m_.version for m_ in ms])
            n_up = c.execute("SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace").fetchone()[0]
            m.down(c, ms, steps=len(ms))
            rest = sorted(r[0] for r in c.execute("SELECT relname FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'"))
            self.assertEqual(rest, ["schema_migrations"])
            m.up(c, ms)
            self.assertEqual(c.execute("SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace").fetchone()[0], n_up)
        from pg import login_dsn
        ensure_logins()
        with psycopg.connect(login_dsn(db, "app_login")) as c, self.assertRaises(psycopg.errors.InsufficientPrivilege):
            c.execute("SELECT * FROM schema_migrations")


if __name__ == "__main__":
    unittest.main()
