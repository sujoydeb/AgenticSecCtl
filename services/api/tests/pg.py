"""Test fixture: a throwaway PostgreSQL in Docker with the product migrations applied."""
import atexit
import os
import subprocess
import time
import uuid
from pathlib import Path

import psycopg

IMAGE = os.environ.get("PG_IMAGE", "postgres:17-alpine")
PASSWORD = "test-only"
ROOT = Path(__file__).resolve().parents[3]
_state: dict = {}


def docker_ok() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _stop():
    if "name" in _state:
        subprocess.run(["docker", "rm", "-f", _state["name"]], capture_output=True)


def server() -> dict:
    """Start one container per test process; return host and port."""
    if _state:
        return _state
    name = "agenticsecctl-pytest-" + uuid.uuid4().hex[:8]
    subprocess.run(["docker", "run", "-d", "--name", name, "-e", f"POSTGRES_PASSWORD={PASSWORD}",
                    "-p", "127.0.0.1::5432", IMAGE], check=True, capture_output=True)
    _state["name"] = name
    atexit.register(_stop)
    out = subprocess.run(["docker", "port", name, "5432/tcp"], check=True, capture_output=True, text=True).stdout
    _state["port"] = int(out.strip().splitlines()[0].rsplit(":", 1)[1])
    for _ in range(120):
        try:
            with psycopg.connect(admin_dsn("postgres"), connect_timeout=2):
                break
        except psycopg.Error:
            time.sleep(0.5)
    else:
        raise RuntimeError("postgres did not start")
    time.sleep(1)  # the image restarts once after init
    return _state


def admin_dsn(db: str) -> str:
    return f"postgresql://postgres:{PASSWORD}@127.0.0.1:{_state['port']}/{db}"


def login_dsn(db: str, user: str) -> str:
    return f"postgresql://{user}:{PASSWORD}@127.0.0.1:{_state['port']}/{db}"


def new_database(migrate: bool = True) -> str:
    """Create an empty database (and the login roles once); optionally apply all migrations as the owner."""
    server()
    db = "t_" + uuid.uuid4().hex[:10]
    with psycopg.connect(admin_dsn("postgres"), autocommit=True) as c:
        c.execute(f"CREATE DATABASE {db}")
    if migrate:
        from agenticsecctl_api import migrate as m
        with psycopg.connect(admin_dsn(db)) as c:
            m.up(c, m.discover())
    if migrate:
        ensure_logins()
    return db


def ensure_logins() -> None:
    """Login roles for the application and the audit writer; cluster-wide, created once, after a migration made the roles."""
    server()
    with psycopg.connect(admin_dsn("postgres"), autocommit=True) as c:
        for login, role in (("app_login", "app_role"), ("audit_login", "audit_writer")):
            if not c.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [login]).fetchone():
                c.execute(f"CREATE ROLE {login} LOGIN PASSWORD '{PASSWORD}' IN ROLE {role}")
