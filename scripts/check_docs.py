#!/usr/bin/env python3
"""Consistency checks across the design documents (stdlib only).

Usage (from repo root): python3 -I scripts/check_docs.py

Checks:
  1. Every FR/NFR/AC reference resolves to a definition in the functional spec.
  2. ADR references are within the defined range (ADR-1..7 in architecture).
  3. TC index in the threat model equals the test catalogue headings.
  4. "Depends on" version citations match the cited document's actual version.
  5. Every FR ID in the spec appears in the generated HTML, and section counts match.
  6. "Section N" references to spec/architecture/threat model exist.
  7. No stale phrases.
Exit code 0 on success, 1 on any failure.
"""
import glob
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
errors = []


def err(msg):
    errors.append(msg)


def read(p):
    return (ROOT / p).read_text(encoding="utf-8")


DOC_FILES = sorted(
    [str(pathlib.Path(p).relative_to(ROOT)) for p in glob.glob(str(ROOT / "Plan" / "*.md"))]
    + [str(pathlib.Path(p).relative_to(ROOT)) for p in glob.glob(str(ROOT / "docs" / "**" / "*.md"), recursive=True)]
    + [str(pathlib.Path(p).relative_to(ROOT)) for p in glob.glob(str(ROOT / "compliance" / "*.md"))]
    + ["CLAUDE.md", "README.md"]
)
texts = {f: read(f) for f in DOC_FILES}
spec = texts["Plan/functional-spec.md"]

# 1. requirement references
fr_defined = set(re.findall(r"^\| (FR-[A-Z]+-\d+) \|", spec, re.M))
nfr_defined = set(re.findall(r"^\| (NFR-\d+) \|", spec, re.M))
ac_defined = set(re.findall(r"^- (AC-\d+)", spec, re.M))
defined = fr_defined | nfr_defined | ac_defined
areas = {d.rsplit("-", 1)[0] for d in fr_defined}
for f, t in texts.items():
    refs = set(re.findall(r"\bFR-[A-Z]+-\d+\b", t)) | set(re.findall(r"\bNFR-\d+\b", t)) | set(re.findall(r"\bAC-\d+\b", t))
    for r in sorted(refs - defined):
        err(f"{f}: undefined reference {r}")
    for a in set(re.findall(r"\b(FR-[A-Z]+)-(?:\d+\.\.\d+|\*)", t)):
        if a not in areas:
            err(f"{f}: unknown requirement area {a}")

# 2. ADR range
for f, t in texts.items():
    bad = set(re.findall(r"ADR-(\d+)", t)) - set("1234567")
    if bad:
        err(f"{f}: ADR ids outside 1..7: {sorted(bad)}")

# 3. test case index parity
tm = texts["Plan/threat-model.md"]
cases = texts["docs/testing/cases.md"]
tm_index = set(re.findall(r"TC-[A-Z]\d+", tm.split("## 7.")[1].split("## 8.")[0]))
catalogue = re.findall(r"^### (TC-[A-Z]\d+) ", cases, re.M)
if len(catalogue) != len(set(catalogue)):
    err("docs/testing/cases.md: duplicate TC headings")
for x in sorted(tm_index - set(catalogue)):
    err(f"TC in threat-model index but not in catalogue: {x}")
for x in sorted(set(catalogue) - tm_index):
    err(f"TC in catalogue but not in threat-model index: {x}")
m = re.search(r"Total: (\d+)", tm)
if m and int(m.group(1)) != len(set(catalogue)):
    err(f"threat-model total {m.group(1)} != catalogue count {len(set(catalogue))}")
m = re.search(r"\| Cases \| (\d+)", cases)
if m and int(m.group(1)) != len(set(catalogue)):
    err(f"catalogue header count {m.group(1)} != {len(set(catalogue))}")

# 4. depends-on versions
short = {
    "functional-spec.md": "Plan/functional-spec.md",
    "architecture.md": "Plan/architecture.md",
    "threat-model.md": "Plan/threat-model.md",
    "cases.md": "docs/testing/cases.md",
    "tech-evaluation.md": "docs/tech-evaluation.md",
    "prd.md": "docs/prd.md",
    "operational-runbook.md": "docs/runbooks/operational-runbook.md",
    "incident-response-playbooks.md": "docs/playbooks/incident-response-playbooks.md",
    "compliance-matrix.md": "compliance/compliance-matrix.md",
}
versions = {}
for name, path in short.items():
    mv = re.search(r"^\| Version \| (\d+\.\d+)", texts[path], re.M)
    versions[name] = mv.group(1) if mv else None
for f in DOC_FILES:
    for line in texts[f].split("\n"):
        if not re.match(r"^\| (Depends on|Companions?) \|", line):
            continue
        for name, ver in re.findall(r"`[^`]*?([\w-]+\.md)`\s*v(\d+\.\d+)", line):
            if name in versions and versions[name] != ver:
                err(f"{f}: cites {name} v{ver} but actual version is v{versions[name]}")

# 5. HTML parity
html_path = ROOT / "Plan" / "functional-spec.html"
if html_path.exists():
    h = html_path.read_text(encoding="utf-8")
    for x in sorted(set(re.findall(r"FR-[A-Z]+-\d+", spec)) - set(re.findall(r"FR-[A-Z]+-\d+", h))):
        err(f"HTML missing {x}")
    if len(re.findall("<h2 ", h)) != len(re.findall(r"^## ", spec, re.M)):
        err("HTML section count differs from markdown")
    v = versions["functional-spec.md"]
    if f"v{v}" not in h:
        err(f"HTML does not mention spec version v{v}")
else:
    err("Plan/functional-spec.html missing")

# 6. section references
sections = {
    "spec": {str(i) for i in range(0, 13)},
    "arch": {str(i) for i in range(1, 14)},
    "tm": {str(i) for i in range(1, 10)},
}
for f, t in texts.items():
    for mm in re.finditer(r"(functional[- ]spec|spec|architecture|threat[- ]model)(?:\.md`?)?(?: v[\d.]+)? (?:\()?Sections? (\d+)", t, re.I):
        w = mm.group(1).lower()
        k = "spec" if "spec" in w else "arch" if w.startswith("arch") else "tm"
        if mm.group(2) not in sections[k]:
            err(f"{f}: bad section reference '{mm.group(0)}'")

# 7. stale phrases (the change log may mention them historically; skip spec Section 0)
stale = [r"to be written", r"does not exist yet", r"design-only with"]
for f, t in texts.items():
    body = t
    if f == "Plan/functional-spec.md":
        body = t.split("## 1. Purpose")[1]
    if f == "CLAUDE.md":
        continue
    for p in stale:
        if re.search(p, body):
            err(f"{f}: stale phrase /{p}/")
    for mm in re.finditer(r"(?<![/\w])testing/cases\.md", body):
        err(f"{f}: path 'testing/cases.md' without docs/ prefix")

if errors:
    print("FAILED:")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(
    f"OK: {len(fr_defined)} FR, {len(nfr_defined)} NFR, {len(ac_defined)} AC, {len(set(catalogue))} TC; "
    f"versions {versions}"
)
