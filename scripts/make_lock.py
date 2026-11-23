#!/usr/bin/env python3
"""Generate hash-pinned lock files for the api package (needs `packaging`, a tooling-only dependency).

    python3 scripts/make_lock.py            # writes services/api/requirements*.lock and prints a licence table
    python3 scripts/make_lock.py --check    # exits non-zero if the files on disk differ from a fresh resolution

How it resolves: starting from the exact pins below, it reads each release's metadata from the package index,
evaluates the environment markers for several target environments (so a lock made on one machine still has
what Linux and an older Python need), keeps the version that is installed in the current environment when it
satisfies every constraint (so the lock matches what the tests ran against) and otherwise the newest
non-prerelease version that does, and records the SHA-256 of EVERY file of each release (all wheels and the
source archive), which is what ``pip install --require-hashes`` needs on any platform.

Install:  pip install --require-hashes -r services/api/requirements.lock
Test:     pip install --require-hashes -r services/api/requirements-test.lock
Optional: pip install --require-hashes -r services/api/requirements-binary.lock   (bundles libpq; LGPL-3.0-only)
Dev/CI:   pip install --require-hashes -r services/api/requirements-dev.lock -r services/api/requirements-binary.lock   (adds ruff and mypy)
"""
from __future__ import annotations

import importlib.metadata as md
import json
import sys
import urllib.request
from pathlib import Path

from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "services/api"
RUNTIME = ["psycopg==3.3.9", "psycopg-pool==3.3.3", "fastapi==0.165.0", "pydantic==2.14.4"]
TEST = ["httpx==0.28.1"]
BINARY = ["psycopg-binary==3.3.9"]
DEV = ["ruff==0.17.6", "mypy==2.4.1"]   # lint and type check gates (scripts/check_all.sh)
# Targets the lock must work for: the supported Python range, Linux (CI and images) and the macOS development machines.
ENVS = [
    {"python_version": v, "python_full_version": f"{v}.0", "sys_platform": sp, "platform_system": ps, "os_name": "posix",
     "implementation_name": "cpython", "platform_python_implementation": "CPython", "platform_machine": "x86_64", "extra": ""}
    for v in ("3.12", "3.13", "3.15") for sp, ps in (("linux", "Linux"), ("darwin", "Darwin"))
]
_cache: dict[tuple[str, str | None], dict] = {}


def fetch(name: str, version: str | None = None) -> dict:
    key = (canonicalize_name(name), version)
    if key not in _cache:
        url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
        with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - fixed https URL
            _cache[key] = json.load(r)
    return _cache[key]


def installed(name: str) -> str | None:
    try:
        return md.version(name)
    except md.PackageNotFoundError:
        return None


def pick(name: str, reqs: list[Requirement]) -> str:
    def ok(v: str) -> bool:
        return all(r.specifier.contains(v, prereleases=True) for r in reqs)
    have = installed(name)
    if have and ok(have):
        return have
    versions = sorted((Version(v) for v in fetch(name)["releases"] if not Version(v).is_prerelease), reverse=True)
    for v in versions:
        if ok(str(v)) and fetch(name)["releases"][str(v)]:
            return str(v)
    raise SystemExit(f"no version of {name} satisfies {[str(r) for r in reqs]}")


def resolve(roots: list[str]) -> dict[str, str]:
    constraints: dict[str, list[Requirement]] = {}
    for r in roots:
        req = Requirement(r)
        constraints.setdefault(canonicalize_name(req.name), []).append(req)
    chosen: dict[str, str] = {}
    for _ in range(20):  # iterate until the set of constraints stops growing
        changed = False
        for name, reqs in sorted(constraints.items()):
            version = pick(reqs[0].name, reqs)
            if chosen.get(name) != version:
                chosen[name], changed = version, True
            for line in fetch(reqs[0].name, version)["info"].get("requires_dist") or []:
                dep = Requirement(line)
                if dep.marker is None:
                    applies = True
                else:
                    applies = any(Marker(str(dep.marker)).evaluate(env) for env in ENVS)
                if dep.extras and dep.marker is not None and "extra" in str(dep.marker):
                    applies = False  # optional extras are not part of the lock
                if applies:
                    dn = canonicalize_name(dep.name)
                    if all(str(dep) != str(x) for x in constraints.get(dn, [])):
                        constraints.setdefault(dn, []).append(dep)
                        changed = True
        if not changed:
            return chosen
    raise SystemExit("resolution did not settle")


def hashes(name: str, version: str) -> list[str]:
    return sorted({f["digests"]["sha256"] for f in fetch(name, version)["urls"]})


def licence(name: str, version: str) -> str:
    info = fetch(name, version)["info"]
    expression = info.get("license_expression")
    if expression:
        return str(expression)
    first_line = (info.get("license") or "").strip().splitlines()
    if first_line:
        return first_line[0][:60]
    classifiers = "; ".join(c.split("::")[-1].strip() for c in info.get("classifiers", []) if c.startswith("License ::"))
    return classifiers or "UNKNOWN"


def render(title: str, pins: dict[str, str], include: str | None = None) -> str:
    lines = [f"# {title}", "# Generated by scripts/make_lock.py from the package index (all release files hashed). Do not edit by hand.",
             "# Targets: Python 3.12 to 3.15, Linux and macOS. Install with: pip install --require-hashes -r <this file>"]
    if include:
        lines.append(f"-r {include}")
    for name in sorted(pins):
        v = pins[name]
        hs = hashes(name, v)
        lines.append(f"{name}=={v} \\")
        lines.append(" \\\n".join(f"    --hash=sha256:{h}" for h in hs))
    return "\n".join(lines) + "\n"


def main() -> int:
    runtime = resolve(RUNTIME)
    full = resolve(RUNTIME + TEST)
    test_only = {k: v for k, v in full.items() if k not in runtime}
    binary = {k: v for k, v in resolve(BINARY).items() if k.startswith("psycopg-binary")}
    dev_all = resolve(RUNTIME + TEST + DEV)
    dev_only = {k: v for k, v in dev_all.items() if k not in full}
    files = {
        "requirements.lock": render("Locked runtime dependencies of the api package", runtime),
        "requirements-test.lock": render("Locked test-only additions (httpx and what it needs) on top of requirements.lock", test_only, "requirements.lock"),
        "requirements-binary.lock": render("Optional: psycopg-binary (bundles libpq; LGPL-3.0-only)", binary),
        "requirements-dev.lock": render("Developer and CI tools (ruff, mypy and what mypy needs) on top of requirements-test.lock", dev_only, "requirements-test.lock"),
    }
    if "--check" in sys.argv:
        bad = [n for n, text in files.items() if (OUT / n).read_text() != text]
        print("lock files are current" if not bad else f"lock files differ: {bad}")
        return 1 if bad else 0
    for n, text in files.items():
        (OUT / n).write_text(text)
    print("| Package | Version | Licence | In |\n|---|---|---|---|")
    for scope, pins in (("runtime", runtime), ("test", test_only), ("binary", binary), ("dev", dev_only)):
        for n, v in sorted(pins.items()):
            print(f"| {n} | {v} | {licence(n, v)} | {scope} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
