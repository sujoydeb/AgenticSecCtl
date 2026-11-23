#!/usr/bin/env python3
"""Run the checks of one work package and save the results (stdlib only).

Usage: python3 -I scripts/run_gate.py WP-1.10 "Title" -- "command 1" "command 2" ...
Writes docs/testing/results/<date>-<wp>.md with a summary table, the exact commands and the full
output of each, and exits non-zero if any command failed. Results describe one run on one machine:
they are evidence, not a certification (docs/testing/results/README.md).
"""
from __future__ import annotations

import datetime as dt
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/testing/results"
TAIL_RE = re.compile(r"^(Ran \d+ tests?.*|OK.*|FAILED.*|PASS.*|ALL CHECKS PASSED|all checks passed|\d+ passed.*)$", re.M)


def sh(cmd: str, cwd: Path) -> tuple[int, str, float]:
    t = time.time()
    p = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=1800)
    return p.returncode, (p.stdout + p.stderr).replace("\r", ""), time.time() - t


def main(argv: list[str]) -> int:
    if len(argv) < 5 or argv[3] != "--":
        print(__doc__)
        return 2
    wp, title, cmds = argv[1], argv[2], argv[4:]
    head = sh("git rev-parse --short HEAD", ROOT)[1].strip()
    dirty = bool(sh("git status --porcelain", ROOT)[1].strip())
    now = dt.datetime.now().astimezone()
    rows, blocks, failed = [], [], 0
    for c in cmds:
        code, out, secs = sh(c, ROOT)
        failed += code != 0
        found = TAIL_RE.findall(out)
        rows.append(f"| `{c}` | {'pass' if code == 0 else '**FAIL**'} | {secs:.1f} s | {found[-1] if found else ''} |")
        blocks.append(f"### `{c}`\n\nExit code {code}.\n\n```text\n{out.rstrip()}\n```\n")
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{now.date()}-{wp.lower()}.md"
    path.write_text(
        f"# Test results: {wp} {title}\n\n"
        f"| | |\n|---|---|\n| Result | **{'PASS' if not failed else 'FAIL'}** ({len(cmds) - failed} of {len(cmds)} commands passed) |\n"
        f"| Run at | {now:%Y-%m-%d %H:%M:%S %z} |\n| Code state | commit `{head}`{' plus uncommitted changes' if dirty else ''} |\n"
        f"| Machine | {platform.system()} {platform.release()}, Python {platform.python_version()} |\n"
        f"| Scope | One run on one developer machine. Evidence for the package gate, not a certification. |\n\n"
        f"## Summary\n\n| Command | Result | Time | Last result line |\n|---|---|---|---|\n" + "\n".join(rows) +
        "\n\n## Output\n\n" + "\n".join(blocks), encoding="utf-8")
    print(f"{'PASS' if not failed else 'FAIL'}: {path.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
