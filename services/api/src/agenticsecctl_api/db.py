"""Database access with the tenant set per transaction (PAR-O-28, IG-9, CTL-22).

The only way to get a connection is ``Database.transaction(tenant)``. It opens a transaction, calls
``set_config('app.tenant_id', <tenant>, true)`` (transaction-local, like SET LOCAL) and yields the
connection; commit or rollback ends the transaction and the setting with it. Nothing here ever sets a
session-level value, a request that gives no tenant gets no rows (row-level security fails closed), and
the pool wipes session state (``DISCARD ALL``) every time a connection is returned, as a second defence.
"""
from __future__ import annotations

import contextlib
import uuid
from collections.abc import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


class TenantError(ValueError):
    pass


def _reset(conn: psycopg.Connection) -> None:
    # DISCARD ALL cannot run inside a transaction block, so run it in autocommit mode and switch back.
    conn.autocommit = True
    try:
        conn.execute("DISCARD ALL")
    finally:
        conn.autocommit = False


def parse_tenant(tenant: object) -> str:
    """A tenant is a canonical UUID string; anything else is refused before it reaches SQL."""
    if not isinstance(tenant, str):
        raise TenantError("tenant must be a UUID string")
    try:
        return str(uuid.UUID(tenant))
    except ValueError:
        raise TenantError("tenant must be a UUID string") from None


class Database:
    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 10, timeout: float = 5.0):
        self._pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size, timeout=timeout, open=False,
                                    reset=_reset, kwargs={"row_factory": dict_row, "autocommit": False,
                                            "prepare_threshold": None})  # DISCARD ALL drops server-side prepared statements
        self._pool.open(wait=True, timeout=timeout)

    @contextlib.contextmanager
    def transaction(self, tenant: object) -> Iterator[psycopg.Connection]:
        tid = parse_tenant(tenant)
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true)", [tid])
            yield conn

    @contextlib.contextmanager
    def unscoped(self) -> Iterator[psycopg.Connection]:
        """A transaction with no tenant: row-level security shows nothing. For health checks and tests."""
        with self._pool.connection() as conn, conn.transaction():
            yield conn

    def close(self) -> None:
        self._pool.close()
