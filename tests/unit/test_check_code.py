"""WP-1.1 tests first: the checks must fail on deliberate violations."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_code.py"


def run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(root)],
                          capture_output=True, text=True)


def make(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)


class Checks(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_clean(self):
        make(self.root, "services/gateway/src/agenticsecctl_gateway/a.py", "import agenticsecctl_common\n")
        self.assertEqual(run(self.root).returncode, 0)

    def test_gateway_importing_api_fails(self):
        gw = "services/gateway/src/agenticsecctl_gateway/a.py"
        make(self.root, gw, "from agenticsecctl_api import x\n")
        r = run(self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("must not import api", r.stdout)

    def test_other_http_client_fails(self):
        make(self.root, "services/api/src/agenticsecctl_api/a.py", "import httpx\n")
        self.assertEqual(run(self.root).returncode, 1)

    def test_http_client_allowed_in_wrapper(self):
        make(self.root, "services/common/src/agenticsecctl_common/http/c.py", "import httpx\n")
        self.assertEqual(run(self.root).returncode, 0)

    def test_dummy_token_fails(self):
        make(self.root, "docs/x.md", "key = AKIA" + "IOSFODNN7EXAMPLE\n")
        r = run(self.root)
        self.assertEqual(r.returncode, 1)
        self.assertIn("secret pattern", r.stdout)


if __name__ == "__main__":
    unittest.main()
