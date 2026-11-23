"""Role bindings read from the ``role_bindings`` table (CTL-23), tenant-scoped by row-level security."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from agenticsecctl_common.auth.roles import Role

from .db import Database

_BY_NAME = {r.db_name: r for r in Role}


class DbRoleStore:
    def __init__(self, db: Database):
        self._db = db

    def active(self, tenant: str, user_id: str, now: datetime, resource: tuple[str, str] | None) -> set[Role]:
        with self._db.transaction(tenant) as c:
            rows = c.execute("SELECT role, scope_type, scope_id FROM role_bindings WHERE user_id = %s AND (expires_at IS NULL OR expires_at > %s)",
                             [user_id, now]).fetchall()
        out: set[Role] = set()
        for r in rows:
            role = _BY_NAME.get(r["role"])
            if role is None:
                continue
            if r["scope_type"] == "tenant" or (resource is not None and (r["scope_type"], str(r["scope_id"])) == resource):
                out.add(role)
        return out


def user_lookup(db: Database) -> Callable[[str, str], str | None]:
    """The (tenant, subject) -> user id function for ``IdentityDirectory``; only active users resolve."""
    def lookup(tenant: str, subject: str) -> str | None:
        try:
            with db.transaction(tenant) as c:
                row = c.execute("SELECT id FROM users WHERE external_subject = %s AND status = 'active'", [subject]).fetchone()
        except ValueError:
            return None
        return str(row["id"]) if row else None
    return lookup
