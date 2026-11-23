#!/usr/bin/env python3
"""Build the policy bundle (WP-1.8, FR-POL-2, CTL-16). Standard library only.

    python3 -I policy/build_bundle.py --out DIR [--max-age SECONDS] [--generated-at RFC3339]
                                      [--registry FILE] [--grants FILE] [--rego DIR]

Writes DIR/bundle.tar.gz in the OPA bundle layout and prints a JSON summary with the bundle hash.

The hash is the SHA-256 of the canonical JSON list of (path, SHA-256 of content) for every ``.rego``
file, so it identifies the policy *code* and does not change when the data snapshot (registry,
grants) or the publication time change. The policy copies it into every decision. ``data.json`` also
carries ``generated_at`` and ``max_age_seconds``; the policy denies once a bundle is older than that
limit, or younger than minus 60 seconds (clock fault). The archive is byte-for-byte reproducible for
the same inputs. Signing (FR-POL-3) is a Phase 3 item and is not done here.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "services/common/src"))
from agenticsecctl_common.canonical import canonicalize  # noqa: E402

DEFAULT_MAX_AGE = 300  # proposal for PAR-O-02, to be confirmed by the security engineer
MAX_AGE_LIMIT = 3600   # hard bound: configuration can never loosen staleness beyond one hour


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def policy_hash(files: list[Path]) -> str:
    entries = [{"path": f"agentic/{f.name}", "sha256": hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]
    return hashlib.sha256(canonicalize(entries)).hexdigest()


def load_object(path: str | None, what: str) -> dict:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        fail(f"cannot read {what}")
    if not isinstance(data, dict):
        fail(f"{what} must be a JSON object")
    return data


def add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.uid, info.gid, info.uname, info.gname, info.mode = len(data), 0, 0, 0, "", "", 0o644
    tar.addfile(info, io.BytesIO(data))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rego", default=str(HERE / "rego"))
    ap.add_argument("--max-age", default=str(DEFAULT_MAX_AGE))
    ap.add_argument("--generated-at")
    ap.add_argument("--registry")
    ap.add_argument("--grants")
    a = ap.parse_args()

    try:
        max_age = int(a.max_age)
    except ValueError:
        fail("--max-age must be an integer number of seconds")
    if not 0 < max_age <= MAX_AGE_LIMIT:
        fail(f"--max-age must be between 1 and {MAX_AGE_LIMIT} seconds")
    generated = a.generated_at or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        dt.datetime.strptime(generated, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail("--generated-at must look like 2026-11-22T12:00:00Z")
    files = sorted(Path(a.rego).glob("*.rego"), key=lambda f: f.name)
    if not files:
        fail("no .rego files found")

    h = policy_hash(files)
    data = {"bundle": {"hash": h, "generated_at": generated, "max_age_seconds": max_age},
            "registry": load_object(a.registry, "registry data"), "grants": load_object(a.grants, "grants data")}
    manifest = {"revision": h, "roots": ["agentic", "bundle", "registry", "grants"]}

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        add(tar, ".manifest", canonicalize(manifest))
        add(tar, "data.json", canonicalize(data))
        for f in files:
            add(tar, f"agentic/{f.name}", f.read_bytes())
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    (out / "bundle.tar.gz").write_bytes(buf.getvalue())
    print(json.dumps({"hash": h, "files": [f.name for f in files], "generated_at": generated, "max_age_seconds": max_age}))


if __name__ == "__main__":
    main()
