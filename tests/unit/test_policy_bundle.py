"""WP-1.8: the policy bundle is built deterministically, carries a content hash, and the built bundle,
evaluated by real OPA, returns decisions that carry that hash (FR-POL-2, CTL-16, TC-Z5)."""
import gzip
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD = ROOT / "policy/build_bundle.py"
OPA = "openpolicyagent/opa@sha256:ff50f50332ff9e722ffafe2658c195ced1f9b6d4f3064000c2ecfa8cdf7acccf"
GEN = "2026-11-22T11:58:00Z"


def build(tmp, *extra, rego=None):
    out = pathlib.Path(tmp)
    cmd = ["python3", "-I", str(BUILD), "--out", str(out), "--generated-at", GEN, *extra]
    if rego:
        cmd += ["--rego", str(rego)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p, out / "bundle.tar.gz"


def members(path):
    with tarfile.open(path, "r:gz") as t:
        return {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}


def docker_ok():
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class Build(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_builds_and_prints_the_hash(self):
        p, path = build(self.tmp.name)
        self.assertEqual(p.returncode, 0, p.stderr)
        info = json.loads(p.stdout)
        self.assertRegex(info["hash"], r"^[0-9a-f]{64}$")
        self.assertTrue(path.exists())

    def test_same_inputs_give_identical_bytes(self):
        a = pathlib.Path(self.tmp.name, "a"); b = pathlib.Path(self.tmp.name, "b")
        a.mkdir(); b.mkdir()
        _, pa = build(a); _, pb = build(b)
        self.assertEqual(pa.read_bytes(), pb.read_bytes())

    def test_hash_is_independent_of_publication_time_and_data(self):
        a = pathlib.Path(self.tmp.name, "a"); b = pathlib.Path(self.tmp.name, "b")
        a.mkdir(); b.mkdir()
        h1 = json.loads(build(a)[0].stdout)["hash"]
        p = subprocess.run(["python3", "-I", str(BUILD), "--out", str(b), "--generated-at", "2027-01-01T00:00:00Z",
                            "--max-age", "600"], capture_output=True, text=True)
        self.assertEqual(json.loads(p.stdout)["hash"], h1)
        self.assertNotEqual((a / "bundle.tar.gz").read_bytes(), (b / "bundle.tar.gz").read_bytes())

    def test_hash_matches_an_independent_computation(self):
        p, path = build(self.tmp.name)
        files = sorted((ROOT / "policy/rego").glob("*.rego"))
        entries = [{"path": f"agentic/{f.name}", "sha256": hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]
        expected = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(json.loads(p.stdout)["hash"], expected)
        m = members(path)
        self.assertEqual(json.loads(m[".manifest"])["revision"], expected)
        self.assertEqual(json.loads(m["data.json"])["bundle"]["hash"], expected)

    def test_any_change_to_policy_text_changes_the_hash(self):
        rego = pathlib.Path(self.tmp.name, "rego"); rego.mkdir()
        for f in (ROOT / "policy/rego").glob("*.rego"):
            shutil.copy(f, rego / f.name)
        out1 = pathlib.Path(self.tmp.name, "o1"); out1.mkdir()
        h1 = json.loads(build(out1, rego=rego)[0].stdout)["hash"]
        f = next(rego.glob("*.rego"))
        for edit in (f.read_text() + "\n", f.read_text().replace("default allow := false", "default allow := true")):
            f.write_text(edit)
            out = pathlib.Path(tempfile.mkdtemp(dir=self.tmp.name))
            self.assertNotEqual(json.loads(build(out, rego=rego)[0].stdout)["hash"], h1)
        (rego / "extra.rego").write_text("package x\n")
        out = pathlib.Path(tempfile.mkdtemp(dir=self.tmp.name))
        self.assertNotEqual(json.loads(build(out, rego=rego)[0].stdout)["hash"], h1)

    def test_tests_are_not_shipped(self):
        _, path = build(self.tmp.name)
        names = set(members(path))
        self.assertEqual(names, {".manifest", "data.json", "agentic/authz.rego"})

    def test_archive_metadata_is_normalised(self):
        _, path = build(self.tmp.name)
        raw = path.read_bytes()
        self.assertEqual(raw[4:8], b"\x00\x00\x00\x00", "gzip header carries no timestamp")
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw))) as t:
            for m in t.getmembers():
                self.assertEqual((m.mtime, m.uid, m.gid, m.uname, m.gname), (0, 0, 0, "", ""))

    def test_data_snapshot_is_embedded_and_empty_by_default(self):
        _, path = build(self.tmp.name)
        d = json.loads(members(path)["data.json"])
        self.assertEqual((d["registry"], d["grants"]), ({}, {}))
        self.assertEqual(d["bundle"]["generated_at"], GEN)
        self.assertEqual(d["bundle"]["max_age_seconds"], 300)

    def test_freshness_limit_is_bounded(self):
        for bad in ("0", "-1", "86401", "abc", "3601"):
            p = subprocess.run(["python3", "-I", str(BUILD), "--out", self.tmp.name, "--generated-at", GEN,
                                "--max-age", bad], capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0, bad)
        p = subprocess.run(["python3", "-I", str(BUILD), "--out", self.tmp.name, "--generated-at", GEN,
                            "--max-age", "3600"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_bad_generated_at_and_missing_rego_are_refused(self):
        p = subprocess.run(["python3", "-I", str(BUILD), "--out", self.tmp.name, "--generated-at", "yesterday"],
                           capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        empty = pathlib.Path(self.tmp.name, "empty"); empty.mkdir()
        p, _ = build(self.tmp.name, rego=empty)
        self.assertNotEqual(p.returncode, 0)

    def test_data_files_must_be_objects(self):
        bad = pathlib.Path(self.tmp.name, "bad.json"); bad.write_text("[1]")
        p, _ = build(self.tmp.name, "--registry", str(bad))
        self.assertNotEqual(p.returncode, 0)


@unittest.skipUnless(docker_ok(), "Docker is not available")
class WithOpa(unittest.TestCase):
    """The built bundle, loaded by OPA itself, returns the decision contract with the bundle hash."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.tmp.name)
        (d / "registry.json").write_text(json.dumps({"agent_server_allow": {"t1": {"a1": {"s1": True}}}}))
        (d / "grants.json").write_text(json.dumps({"t1": {"a1": [
            {"tool": "s1__read_doc", "action_classes": ["read"], "resource_pattern": "docs/*"}]}}))
        p, cls.path = build(d, "--registry", str(d / "registry.json"), "--grants", str(d / "grants.json"))
        assert p.returncode == 0, p.stderr
        cls.hash = json.loads(p.stdout)["hash"]
        cls.dir = d

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def decide(self, **patch):
        inp = {"tenant": "t1", "agent": {"id": "a1", "status": "active"}, "server": {"id": "s1", "status": "approved"},
               "tool": {"id": "s1__read_doc", "status": "approved", "action_class": "read", "classification": "Internal",
                        "hash_ok": True},
               "resource": "docs/x", "args_digest": "sha256:abc", "approval": {"valid": False},
               "now": "2026-11-22T12:00:00Z"}
        inp.update(patch)
        p = subprocess.run(["docker", "run", "--rm", "-i", "-v", f"{self.dir}:/w:ro", OPA, "eval", "-b", "/w/bundle.tar.gz",
                            "--stdin-input", "-f", "json", "data.agentic.authz.decision"],
                           input=json.dumps(inp), capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)["result"][0]["expressions"][0]["value"]

    def test_allow_carries_the_bundle_hash(self):
        d = self.decide()
        self.assertTrue(d["allow"])
        self.assertEqual(d["policy_hash"], self.hash)

    def test_deny_carries_the_bundle_hash_and_reasons(self):
        d = self.decide(agent={"id": "ghost", "status": "active"})
        self.assertFalse(d["allow"])
        self.assertIn("agent_server_not_allowed", d["reasons"])
        self.assertEqual(d["policy_hash"], self.hash)

    def test_stale_bundle_denies(self):
        d = self.decide(now="2026-11-22T12:03:00Z")  # generated 11:58:00, limit 300 s
        self.assertFalse(d["allow"])
        self.assertIn("bundle_stale", d["reasons"])

    def test_empty_input_denies(self):
        d = self.decide(tenant=None, agent=None)
        self.assertFalse(d["allow"])
        self.assertEqual(d["policy_hash"], self.hash)


if __name__ == "__main__":
    unittest.main()
