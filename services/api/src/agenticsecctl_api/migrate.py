"""Database migration runner (PAR-O-27: plain SQL files plus this small runner).

Files live in ``db/migrations`` as ``NNNN_name.up.sql`` and ``NNNN_name.down.sql``. Rules:

* versions are contiguous from 1 and every migration has both files (rollback is always possible);
* each migration runs in its own transaction, so a failure leaves nothing half applied;
* the checksum of an applied migration is recorded; editing it afterwards is refused
  (changes go in a new migration, expand and contract);
* one runner at a time: a PostgreSQL advisory lock serialises concurrent runs;
* it connects as the migration role; the application roles cannot see ``schema_migrations``.

Command line: ``AGENTIC_MIGRATE_DSN=... python -m agenticsecctl_api.migrate up|down|status [--steps N]``.
The DSN comes from the environment, never from an argument, so it does not appear in process listings.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg

DEFAULT_DIR = Path(__file__).resolve().parents[4] / "db" / "migrations"
_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$")
_LOCK_KEY = 0x41534330  # arbitrary constant: "ASC0"

_BOOKKEEPING = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version int PRIMARY KEY,
  name text NOT NULL,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON schema_migrations FROM PUBLIC;
"""


class MigrationError(Exception):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    up: str
    down: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.up.encode("utf-8")).hexdigest()


def discover(directory: Path = DEFAULT_DIR) -> list[Migration]:
    files: dict[int, dict[str, tuple[str, str]]] = {}
    for f in sorted(Path(directory).glob("*.sql")):
        m = _NAME.match(f.name)
        if not m:
            raise MigrationError(f"unexpected file in migrations directory: {f.name}")
        files.setdefault(int(m.group(1)), {})[m.group(3)] = (m.group(2), f.read_text(encoding="utf-8"))
    out: list[Migration] = []
    for i, version in enumerate(sorted(files), start=1):
        if version != i:
            raise MigrationError(f"migration versions must be contiguous from 1; found {version} where {i} was expected")
        parts = files[version]
        if set(parts) != {"up", "down"}:
            raise MigrationError(f"migration {version:04d} needs both an up and a down file")
        if parts["up"][0] != parts["down"][0]:
            raise MigrationError(f"migration {version:04d}: up and down files have different names")
        out.append(Migration(version, parts["up"][0], parts["up"][1], parts["down"][1]))
    return out


def _applied(conn: psycopg.Connection) -> dict[int, tuple[str, str]]:
    return {v: (n, c) for v, n, c in conn.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version")}


def _prepare(conn: psycopg.Connection) -> None:
    conn.execute("SELECT pg_advisory_lock(%s)", [_LOCK_KEY])
    conn.execute(_BOOKKEEPING)
    conn.commit()


def _verify(applied: dict[int, tuple[str, str]], migrations: list[Migration]) -> None:
    by_version = {m.version: m for m in migrations}
    for v, (name, checksum) in applied.items():
        m = by_version.get(v)
        if m is None:
            raise MigrationError(f"database has migration {v:04d} that this checkout does not contain")
        if m.checksum != checksum or m.name != name:
            raise MigrationError(f"migration {v:04d} was edited after it was applied; add a new migration instead")
    if sorted(applied) != list(range(1, len(applied) + 1)):
        raise MigrationError("applied migrations are not contiguous")


def up(conn: psycopg.Connection, migrations: list[Migration], target: int | None = None) -> list[int]:
    """Apply pending migrations in order (up to ``target``). Returns the versions applied."""
    _prepare(conn)
    done: list[int] = []
    try:
        applied = _applied(conn)
        conn.commit()
        _verify(applied, migrations)
        for m in migrations:
            if m.version in applied or (target is not None and m.version > target):
                continue
            try:
                with conn.transaction():
                    conn.execute(m.up)  # type: ignore[arg-type,unused-ignore]
                    conn.execute("INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                                 [m.version, m.name, m.checksum])
            except psycopg.Error as exc:
                raise MigrationError(f"migration {m.version:04d} failed and was rolled back: {exc.diag.message_primary or type(exc).__name__}") from exc
            done.append(m.version)
    finally:
        conn.rollback()
        conn.execute("SELECT pg_advisory_unlock(%s)", [_LOCK_KEY])
        conn.commit()
    return done


def down(conn: psycopg.Connection, migrations: list[Migration], steps: int = 1) -> list[int]:
    """Roll back the latest ``steps`` migrations, newest first. Returns the versions rolled back."""
    if steps < 1:
        raise MigrationError("steps must be at least 1")
    _prepare(conn)
    done: list[int] = []
    try:
        applied = _applied(conn)
        conn.commit()
        _verify(applied, migrations)
        by_version = {m.version: m for m in migrations}
        for v in sorted(applied, reverse=True)[:steps]:
            try:
                with conn.transaction():
                    conn.execute(by_version[v].down)  # type: ignore[arg-type,unused-ignore]
                    conn.execute("DELETE FROM schema_migrations WHERE version = %s", [v])
            except psycopg.Error as exc:
                raise MigrationError(f"rollback of {v:04d} failed and was undone: {exc.diag.message_primary or type(exc).__name__}") from exc
            done.append(v)
    finally:
        conn.rollback()
        conn.execute("SELECT pg_advisory_unlock(%s)", [_LOCK_KEY])
        conn.commit()
    return done


def status(conn: psycopg.Connection, migrations: list[Migration]) -> list[tuple[int, str, str]]:
    _prepare(conn)
    try:
        applied = _applied(conn)
        conn.commit()
        _verify(applied, migrations)
        return [(m.version, m.name, "applied" if m.version in applied else "pending") for m in migrations]
    finally:
        conn.rollback()
        conn.execute("SELECT pg_advisory_unlock(%s)", [_LOCK_KEY])
        conn.commit()


def main(argv: list[str]) -> int:
    dsn = os.environ.get("AGENTIC_MIGRATE_DSN")
    if not dsn or not argv or argv[0] not in {"up", "down", "status"}:
        print("usage: AGENTIC_MIGRATE_DSN=... python -m agenticsecctl_api.migrate up|down|status [--steps N]", file=sys.stderr)
        return 2
    steps = int(argv[argv.index("--steps") + 1]) if "--steps" in argv else 1
    try:
        migrations = discover(Path(os.environ.get("AGENTIC_MIGRATIONS_DIR", DEFAULT_DIR)))
        with psycopg.connect(dsn, autocommit=False) as conn:
            if argv[0] == "up":
                print("applied:", up(conn, migrations) or "nothing to do")
            elif argv[0] == "down":
                print("rolled back:", down(conn, migrations, steps) or "nothing to do")
            else:
                for v, n, s in status(conn, migrations):
                    print(f"{v:04d} {n} {s}")
    except (MigrationError, psycopg.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
