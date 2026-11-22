#!/usr/bin/env python3
"""Rewrite version citations in 'Depends on' and 'Companion' header rows to the actual document versions.

Usage: python3 -I scripts/sync_versions.py            (rewrites files in place)
       python3 -I scripts/sync_versions.py --check    (reports what would change; exit 1 if anything)

Run after bumping a document's own version. scripts/check_docs.py performs the same comparison as a check.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
files = [
    f for f in subprocess.check_output(["git", "ls-files", "-o", "-c", "--exclude-standard", "*.md"], cwd=ROOT).decode().split()
    if f != "controls/catalogue.md"
]
files = [f for f in files if not f.startswith(("services/", "tests/"))]
versions = {}
for f in files:
    m = re.search(r"^\| Version \| (\d+\.\d+)", (ROOT / f).read_text(encoding="utf-8"), re.M)
    if m:
        versions[pathlib.Path(f).name] = m.group(1)
cat = ROOT / "controls" / "catalogue.md"
if cat.exists():
    m = re.search(r"^\| Version \| (\d+\.\d+)", cat.read_text(encoding="utf-8"), re.M)
    if m:
        versions["catalogue.md"] = m.group(1)
check_only = "--check" in sys.argv
changed = 0
for f in files + (["controls/catalogue.md"] if False else []):
    path = ROOT / f
    text = path.read_text(encoding="utf-8")
    out = []
    for line in text.split("\n"):
        if re.match(r"^\| (Depends on|Companions?) \|", line):
            new = re.sub(
                r"`([^`]*?([\w-]+\.md))`\s*v\d+\.\d+",
                lambda m: f"`{m.group(1)}` v{versions[m.group(2)]}" if m.group(2) in versions else m.group(0),
                line,
            )
            if new != line:
                changed += 1
                print(f"{f}: {line[:60]}... -> updated")
                line = new
        out.append(line)
    if not check_only:
        path.write_text("\n".join(out), encoding="utf-8")
print(f"{changed} line(s) {'would change' if check_only else 'updated'}")
sys.exit(1 if (check_only and changed) else 0)
