#!/usr/bin/env python3
"""Mutation check: weaken the code in one named way, run its tests, require a failure, restore the file.

Usage: python3 -I scripts/run_mutations.py WP-1.10 "Title" MUTATION_FILE.json
The JSON file is a list of {file, old, new, label, test}. Writes docs/testing/results/<date>-<wp>-mutations.md and
exits non-zero if any mutation survives (tests still pass) or a file could not be restored.
"""
from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str]) -> int:
    wp, title, spec = argv[1], argv[2], json.loads(Path(argv[3]).read_text())
    rows, survived = [], 0
    for m in spec:
        f = ROOT / m["file"]
        orig = f.read_text()
        if m["old"] not in orig:
            rows.append(f"| {m['label']} | `{m['file']}` | **mutation did not apply** | |")
            survived += 1
            continue
        try:
            f.write_text(orig.replace(m["old"], m["new"], 1))
            p = subprocess.run(m["test"], shell=True, cwd=ROOT, capture_output=True, text=True, timeout=900)
        finally:
            f.write_text(orig)
        killed = p.returncode != 0
        survived += not killed
        tail = [l for l in (p.stdout + p.stderr).splitlines() if l.startswith(("FAILED", "FAIL:", "OK", "PASS:", "Ran "))]
        rows.append(f"| {m['label']} | `{m['file']}` | {'caught' if killed else '**SURVIVED**'} | {'; '.join(tail[-2:])} |")
    now = dt.datetime.now().astimezone()
    out = ROOT / "docs/testing/results" / f"{now.date()}-{wp.lower()}-mutations.md"
    out.write_text(
        f"# Mutation check: {wp} {title}\n\n| | |\n|---|---|\n| Result | **{'PASS' if not survived else 'FAIL'}**: "
        f"{len(spec) - survived} of {len(spec)} mutations caught |\n| Run at | {now:%Y-%m-%d %H:%M:%S %z} |\n"
        f"| Method | Each mutation weakens the code in one way, the package tests run, a failure is expected, the file is restored. "
        f"Run by `scripts/run_mutations.py`. |\n\n| Mutation | File | Outcome | Test result |\n|---|---|---|---|\n" + "\n".join(rows) + "\n",
        encoding="utf-8")
    print(f"{'PASS' if not survived else 'FAIL'}: {out.relative_to(ROOT)}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
