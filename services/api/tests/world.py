"""Shared test setup: one migrated database per test module, a fresh tenant with users per test."""
import uuid
from dataclasses import dataclass

import psycopg
from pg import admin_dsn, login_dsn, new_database

from agenticsecctl_api.db import Database
from agenticsecctl_api.registry import Actor
from agenticsecctl_common.http import Guard

PUBLIC_IP = "93.184.216.34"
GUARD = Guard(resolver=lambda host, port: [PUBLIC_IP], environment="test")


@dataclass
class Tenant:
    id: str
    users: dict
    def actor(self, who: str) -> Actor:
        return Actor(self.users[who], self.id)


class Env:
    def __init__(self):
        self.dbname = new_database()
        self.app = Database(login_dsn(self.dbname, "app_login"), min_size=1, max_size=4)
        self.audit = Database(login_dsn(self.dbname, "audit_login"), min_size=1, max_size=4)
        self.dispatch = Database(login_dsn(self.dbname, "dispatch_login"), min_size=1, max_size=8)

    def admin(self):
        return psycopg.connect(admin_dsn(self.dbname), autocommit=True)

    def tenant(self, name=None) -> Tenant:
        tid = str(uuid.uuid4())
        users = {n: str(uuid.uuid4()) for n in ("alice", "eve", "amir", "anna", "ben")}
        with self.admin() as c:
            c.execute("INSERT INTO tenants (id, name) VALUES (%s, %s)", [tid, name or "t-" + tid[:8]])
            for n, u in users.items():
                c.execute("INSERT INTO users (id, tenant_id, external_subject) VALUES (%s, %s, %s)", [u, tid, n + "-" + tid[:6]])
        return Tenant(tid, users)

    def close(self):
        self.app.close(); self.audit.close(); self.dispatch.close()
