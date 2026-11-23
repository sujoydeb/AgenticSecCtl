"""WP-1.7 isolation test (plan IG-6): from the worker container a direct database connection and a connection to an
internal address both fail; only the API is reachable. Real containers on real Docker networks.

Topology under test (the same one the deployment must give the worker):
    scan network (internal, no route out):  worker, api
    control network (internal):             api, postgres
The worker is attached to the scan network only, runs unprivileged on a read-only file system with no capabilities,
and holds no credential except what the test passes in (nothing).
"""
import json
import pathlib
import subprocess
import sys
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services/api/tests"))
import pg  # noqa: E402

IMAGE = "python:3.12-slim"
PROBE = r"""
import json, os, socket, sys
def tcp(host, port, t=2.0):
    try:
        socket.create_connection((host, port), t).close(); return True
    except OSError: return False
def writable(path):
    try:
        open(os.path.join(path, "probe"), "w").close(); return True
    except OSError: return False
out = {"api": tcp(sys.argv[1], 8080), "db_by_name": tcp(sys.argv[2], 5432), "db_by_ip": tcp(sys.argv[3], 5432),
       "metadata": tcp("169.254.169.254", 80), "external": tcp("1.1.1.1", 443), "private": tcp("10.0.0.1", 80),
       "uid": os.getuid(), "write_root": writable("/"), "write_app": writable("/app"), "write_tmp": writable("/tmp"),
       "secret_env": sorted(k for k in os.environ if k != "GPG_KEY" and any(w in k.upper() for w in ("PASS", "SECRET", "TOKEN", "DSN", "KEY", "DATABASE", "PG")))}  # GPG_KEY: the base image's public release-signing key ID, not a secret
try:
    import agenticsecctl_scanner.scan, agenticsecctl_scanner.importer  # the code itself loads from the read-only mounts
    out["code_loads"] = True
except Exception as e:
    out["code_loads"] = repr(e)
print(json.dumps(out))
"""


def sh(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=180)


@unittest.skipUnless(pg.docker_ok(), "Docker is not available")
class WorkerIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tag = uuid.uuid4().hex[:8]
        cls.scan, cls.ctl, cls.stub = f"ascl-scan-{tag}", f"ascl-ctl-{tag}", f"ascl-api-{tag}"
        sh("docker", "network", "create", "--internal", cls.scan)
        sh("docker", "network", "create", "--internal", cls.ctl)
        sh("docker", "run", "-d", "--name", cls.stub, "--network", cls.scan, IMAGE, "python", "-m", "http.server", "8080")
        sh("docker", "network", "connect", cls.ctl, cls.stub)
        cls.pg_name = pg.server()["name"]
        sh("docker", "network", "connect", cls.ctl, cls.pg_name)
        fmt = '{{(index .NetworkSettings.Networks "%s").IPAddress}}'
        cls.pg_ip = sh("docker", "inspect", "-f", fmt % cls.ctl, cls.pg_name).stdout.strip()
        cls.api_ip = sh("docker", "inspect", "-f", fmt % cls.scan, cls.stub).stdout.strip()
        cls.result = cls.run_worker()

    @classmethod
    def run_worker(cls, network=None):
        r = sh("docker", "run", "--rm", "--network", network or cls.scan, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--user", "65534:65534", "--pids-limit", "64", "--memory", "256m", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
               "-v", f"{ROOT / 'services/common/src'}:/app/common:ro", "-v", f"{ROOT / 'services/scanner/src'}:/app/scanner:ro",
               "-e", "PYTHONPATH=/app/common:/app/scanner", "-e", "PYTHONDONTWRITEBYTECODE=1", "-w", "/app",
               IMAGE, "python", "-c", PROBE, cls.stub, cls.pg_name, cls.pg_ip)
        return json.loads(r.stdout.strip().splitlines()[-1])

    @classmethod
    def tearDownClass(cls):
        sh("docker", "rm", "-f", cls.stub, check=False)
        sh("docker", "network", "disconnect", "-f", cls.ctl, cls.pg_name, check=False)
        sh("docker", "network", "rm", cls.scan, cls.ctl, check=False)

    def test_the_worker_reaches_the_api_and_nothing_else(self):
        self.assertTrue(self.result["api"], "the worker must be able to reach the API")
        for target in ("db_by_name", "db_by_ip", "metadata", "external", "private"):
            self.assertFalse(self.result[target], f"worker could reach {target}")

    def test_the_worker_is_unprivileged_and_the_file_system_is_read_only(self):
        self.assertEqual(self.result["uid"], 65534)
        self.assertFalse(self.result["write_root"])
        self.assertFalse(self.result["write_app"])
        self.assertTrue(self.result["write_tmp"])   # scratch space only, mounted noexec

    def test_the_worker_holds_no_database_credential_or_secret(self):
        self.assertEqual(self.result["secret_env"], [])

    def test_the_scanner_code_runs_from_read_only_mounts(self):
        self.assertIs(self.result["code_loads"], True)

    def test_the_isolation_probe_can_fail(self):
        """Control: on the control network the same probe does reach the database, so the checks above mean something."""
        r = sh("docker", "run", "--rm", "--network", self.ctl, IMAGE, "python", "-c",
               "import socket,sys; socket.create_connection((sys.argv[1], 5432), 3).close(); print('reached')", self.pg_ip)
        self.assertEqual(r.stdout.strip(), "reached")


if __name__ == "__main__":
    unittest.main()
