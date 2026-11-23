"""The lock files stay consistent with pyproject.toml and carry a hash for every pin."""
import pathlib
import re
import tomllib
import unittest

API = pathlib.Path(__file__).resolve().parents[2] / "services/api"


def pins(path):
    out = {}
    text = (API / path).read_text()
    for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text):
        m = re.match(r"([A-Za-z0-9_.-]+)==([^\s\\]+)", block)
        if m:
            out[m.group(1).lower().replace("_", "-")] = (m.group(2), re.findall(r"--hash=sha256:([0-9a-f]{64})", block))
    return out


class Locks(unittest.TestCase):
    def test_every_pin_has_hashes_and_nothing_is_unpinned(self):
        for name in ("requirements.lock", "requirements-test.lock", "requirements-binary.lock"):
            text = (API / name).read_text()
            for line in text.splitlines():
                if line and not line.startswith(("#", " ", "-r ")):
                    self.assertRegex(line, r"^[A-Za-z0-9_.-]+==[^\s]+ \\$", f"{name}: {line}")
            for pkg, (_, hashes) in pins(name).items():
                self.assertGreaterEqual(len(hashes), 1, f"{name}: {pkg} has no hash")
                self.assertEqual(len(hashes), len(set(hashes)), f"{name}: {pkg} repeats a hash")

    def test_pyproject_pins_equal_the_lock(self):
        project = tomllib.loads((API / "pyproject.toml").read_text())["project"]
        runtime, test, binary = pins("requirements.lock"), pins("requirements-test.lock"), pins("requirements-binary.lock")
        everything = {**runtime, **test, **binary}
        wanted = project["dependencies"] + project["optional-dependencies"]["test"] + project["optional-dependencies"]["binary"]
        for dep in wanted:
            name, version = re.match(r"([A-Za-z0-9_.-]+)==([0-9][^\s;]*)", dep).groups()
            self.assertEqual(everything[name.lower().replace("_", "-")][0], version, dep)

    def test_runtime_lock_has_no_test_only_packages(self):
        self.assertFalse({"httpx", "httpcore", "h11", "certifi"} & set(pins("requirements.lock")))

    def test_the_test_lock_includes_the_runtime_lock(self):
        self.assertIn("-r requirements.lock", (API / "requirements-test.lock").read_text())

    def test_no_package_is_in_two_locks_with_different_versions(self):
        a, b, c = pins("requirements.lock"), pins("requirements-test.lock"), pins("requirements-binary.lock")
        for x, y in ((a, b), (a, c), (b, c)):
            for k in set(x) & set(y):
                self.assertEqual(x[k][0], y[k][0], k)


if __name__ == "__main__":
    unittest.main()
