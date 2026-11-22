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
  8. Control catalogue structure, ID resolution, threat coverage and freshness of the generated file.
  10. Markdown relative links resolve; tables have consistent column counts; Mermaid blocks are
     structurally sane; TC references resolve in every document; stated counts match actual counts.
  11. Parameter register (fixed values still stated by the listed files; every control with a
     'to be set' parameter appears in the open-parameter table) and corpus files (JSON Lines).
  9. Active GitHub workflows: top-level permissions, actions pinned to commit SHAs (or a recorded
     waiver), no pull_request_target; the CI template keeps its warning header.
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
    + [str(pathlib.Path(p).relative_to(ROOT)) for p in glob.glob(str(ROOT / "controls" / "*.md"))]
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
    "catalogue.md": "controls/catalogue.md",
    "ci-cd-pipeline.md": "docs/ci-cd-pipeline.md",
    "deployment-architecture.md": "docs/deployment-architecture.md",
    "roadmap.md": "docs/roadmap.md",
    "architecture-assessment.md": "docs/architecture-assessment.md",
    "data-model.md": "docs/data-model.md",
    "api-specification.md": "docs/api-specification.md",
    "governance.md": "docs/governance.md",
    "reviewgap.md": "docs/reviewgap.md",
    "mcp-compatibility.md": "docs/mcp-compatibility.md",
    "authn-authz-design.md": "docs/authn-authz-design.md",
    "cross-cutting-design.md": "docs/cross-cutting-design.md",
    "ux-outline.md": "docs/ux-outline.md",
    "parameter-register.md": "docs/parameter-register.md",
    "performance-test-plan.md": "docs/testing/performance-test-plan.md",
    "fixtures-and-corpora.md": "docs/testing/fixtures-and-corpora.md",
    "privacy-assessment.md": "docs/privacy-assessment.md",
    "customer-inputs.md": "docs/customer-inputs.md",
    "cloud-adapter-verification.md": "docs/cloud-adapter-verification.md",
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
    "arch": {str(i) for i in range(1, 15)},
    "tm": {str(i) for i in range(1, 10)},
}
for f, t in texts.items():
    for mm in re.finditer(r"(?<!deployment )(?<!deployment-)(functional[- ]spec|spec|architecture|threat[- ]model)(?:\.md`?)?(?: v[\d.]+)? (?:\()?Sections? (\d+)", t, re.I):
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


# 8. control catalogue (controls/catalogue.yaml is the source; controls/catalogue.md is generated)
sys.path.insert(0, str(ROOT / "scripts"))
import catalogue_lib  # noqa: E402

cat_path = ROOT / "controls" / "catalogue.yaml"
if not cat_path.exists():
    err("controls/catalogue.yaml missing")
else:
    try:
        cat = catalogue_lib.load(str(cat_path))
    except catalogue_lib.CatalogueError as exc:
        err(f"catalogue: {exc}")
        cat = None
    if cat:
        for pr in catalogue_lib.validate_structure(cat):
            err(f"catalogue: {pr}")
        ctl_ids = [c["id"] for c in cat["controls"]]
        other_ids = set(ctl_ids)
        valid_threats = set("ABCDEFGHIJKLMNOP") | {f"X{i}" for i in range(1, 15)}
        sod_defined = set(re.findall(r"\b(SoD-\d+)\b", spec))
        for c in cat["controls"]:
            cid = c["id"]
            for r in catalogue_lib.expand_ids(c["requirements"]):
                if r.startswith(("FR-", "NFR-")) and r not in (fr_defined | nfr_defined):
                    err(f"catalogue {cid}: requirement {r} not defined in spec")
                elif r.startswith("SoD-") and r not in sod_defined:
                    err(f"catalogue {cid}: {r} not defined in spec")
            for tc in catalogue_lib.expand_ids(c["tests"]):
                if tc not in set(catalogue):
                    err(f"catalogue {cid}: test {tc} not in docs/testing/cases.md")
            for th in c["threats"]:
                if th not in valid_threats:
                    err(f"catalogue {cid}: invalid threat {th}")
            for d in c["depends_on"]:
                if d not in other_ids:
                    err(f"catalogue {cid}: depends_on {d} is not a control")
                if d == cid:
                    err(f"catalogue {cid}: depends on itself")
        # IDs must match the compliance matrix Section 3 and be used by its mappings
        matrix = texts["compliance/compliance-matrix.md"]
        sec3 = matrix.split("## 3.")[1].split("## 4.")[0]
        matrix_ids = re.findall(r"^\| (CTL-\d+) \|", sec3, re.M)
        if sorted(matrix_ids) != sorted(ctl_ids):
            err(f"matrix Section 3 control IDs differ from catalogue: {sorted(set(matrix_ids) ^ set(ctl_ids))}")
        for mid in set(re.findall(r"\bCTL-\d+\b", matrix)):
            if mid not in other_ids:
                err(f"compliance matrix references unknown control {mid}")
        # every threat must be covered by at least one control
        covered = {t for c in cat["controls"] for t in c["threats"]}
        for th in sorted(valid_threats - covered):
            err(f"threat {th} is not covered by any control in the catalogue")
        # generated markdown must be up to date
        md_path = ROOT / "controls" / "catalogue.md"
        if not md_path.exists():
            err("controls/catalogue.md missing (run scripts/build_catalogue_md.py)")
        elif md_path.read_text(encoding="utf-8") != catalogue_lib.render_markdown(cat):
            err("controls/catalogue.md is stale (run scripts/build_catalogue_md.py)")


# 9. pipeline rules for active workflows (docs/ci-cd-pipeline.md Sections 7 and 8)
pipeline_doc = texts.get("docs/ci-cd-pipeline.md", "")
waivers = set(re.findall(r"^\| (W-\d+) \|", pipeline_doc, re.M))
for wf in sorted(glob.glob(str(ROOT / ".github" / "workflows" / "*.y*ml"))):
    rel = str(pathlib.Path(wf).relative_to(ROOT))
    lines = pathlib.Path(wf).read_text(encoding="utf-8").split("\n")
    if not re.search(r"^permissions:", "\n".join(lines), re.M):
        err(f"{rel}: missing top-level permissions block")
    for i, ln in enumerate(lines):
        m = re.search(r"uses:\s*([^\s#]+)", ln)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref):
            continue
        prev = lines[i - 1] if i else ""
        w = re.search(r"waiver:\s*(W-\d+)", prev + " " + ln)
        if not w:
            err(f"{rel}:{i + 1}: action {ref} is not pinned to a commit SHA and has no waiver comment")
        elif w.group(1) not in waivers:
            err(f"{rel}:{i + 1}: waiver {w.group(1)} is not recorded in docs/ci-cd-pipeline.md Section 7")
    if "pull_request_target" in "\n".join(lines):
        err(f"{rel}: pull_request_target is not allowed (docs/ci-cd-pipeline.md Section 8)")
tpl = ROOT / "docs" / "ci-templates" / "product-security-gates.yml"
if tpl.exists() and "TEMPLATE, NOT AN ACTIVE WORKFLOW" not in tpl.read_text(encoding="utf-8"):
    err("docs/ci-templates/product-security-gates.yml lost its template warning header")


# 10. structure and counts across all documents
import json  # noqa: E402

tc_all = set(catalogue)
cat_count = len(cat["controls"]) if cat else 0
for f, t in texts.items():
    base = pathlib.Path(f).parent
    # relative links
    for lm in re.finditer(r"\[[^\]]*\]\(([^)\s]+)\)", t):
        target = lm.group(1)
        if re.match(r"^(https?:|mailto:|#)", target):
            continue
        path = (ROOT / base / target.split("#")[0]).resolve()
        if not path.exists():
            err(f"{f}: broken relative link {target}")
    # table column consistency
    block_rows = []
    for ln in t.split("\n") + [""]:
        if ln.startswith("|"):
            block_rows.append(re.sub(r"`[^`]*`", "", ln).replace("\\|", "").count("|"))
        else:
            if block_rows and len(set(block_rows)) > 1:
                err(f"{f}: table with inconsistent column counts {sorted(set(block_rows))} near '{ln[:40]}'")
            block_rows = []
    # mermaid
    for mb in re.finditer(r"```mermaid\n(.*?)```", t, re.S):
        body = mb.group(1)
        first = next((l.strip() for l in body.split("\n") if l.strip()), "")
        if not re.match(r"^(flowchart|graph|sequenceDiagram|erDiagram|classDiagram|stateDiagram|gantt|journey|pie)", first):
            err(f"{f}: mermaid block starts with unknown diagram type '{first[:30]}'")
        if first.startswith(("flowchart", "graph")):
            if body.count("[") != body.count("]") or body.count("{") != body.count("}"):
                err(f"{f}: mermaid flowchart has unbalanced brackets")
            if len(re.findall(r"^\s*subgraph\b", body, re.M)) != len(re.findall(r"^\s*end\s*$", body, re.M)):
                err(f"{f}: mermaid subgraph/end mismatch")
    # TC references
    for ref in set(re.findall(r"\bTC-[A-Z]\d+\b", t)):
        if ref not in tc_all:
            err(f"{f}: reference to unknown test case {ref}")
    for lo, hi_letter, hi in re.findall(r"\b(TC-[A-Z]\d+)\.\.([A-Z]?)(\d+)\b", t):
        letter = lo[3]
        a = int(lo[4:])
        for n in range(a, int(hi) + 1):
            if f"TC-{letter}{n}" not in tc_all:
                err(f"{f}: range {lo}..{hi_letter}{hi} includes unknown case TC-{letter}{n}")

# stated counts
count_checks = [
    ("README.md", r"cases\.md`, (\d+) cases", len(tc_all), "test cases"),
    ("README.md", r"(\d+) controls, CTL-01\.\.\d+", cat_count, "controls"),
    ("CLAUDE.md", r"\| (\d+) security test cases", len(tc_all), "test cases"),
    ("CLAUDE.md", r"\(CTL-01\.\.(\d+)\)", cat_count, "controls"),
    ("docs/prd.md", r"\((\d+) TC-\* cases", len(tc_all), "test cases"),
    ("docs/testing/cases.md", r"\| Cases \| (\d+) ", len(tc_all), "test cases"),
    ("Plan/threat-model.md", r"Total: (\d+) \(", len(tc_all), "test cases"),
    ("Plan/functional-spec.md", r"\((\d+) cases; threat-model Section 7", len(tc_all), "test cases"),
    ("docs/roadmap.md", r"test catalogue \((\d+) cases\)", len(tc_all), "test cases"),
    ("docs/governance.md", r"CTL-01\.\.(\d+)\)", cat_count, "controls"),
]
for f, pat, actual, what in count_checks:
    for mm in re.finditer(pat, texts.get(f, "")):
        if int(mm.group(1)) != actual:
            err(f"{f}: states {mm.group(1)} {what} but actual is {actual}")
# phase totals sentence in the test catalogue
ph = {}
for mm in re.finditer(r"^### (TC-[A-Z]\d+) .*\n\*Threat [^\n]*· (P\d)(?:/P\d)?(?: · (MVP))?\*", cases, re.M):
    ph.setdefault(mm.group(2), []).append(bool(mm.group(3)))
ms = re.search(r"Phase 1 has (\d+) cases \((\d+) MVP-gating\), Phase 2 has (\d+), Phase 3 has (\d+), Phase 4 has (\d+), Phase 5 has (\d+) \(total (\d+)\)", cases)
if ms:
    want = [len(ph.get("P1", [])), sum(ph.get("P1", [])), len(ph.get("P2", [])), len(ph.get("P3", [])), len(ph.get("P4", [])), len(ph.get("P5", [])), len(tc_all)]
    if [int(x) for x in ms.groups()] != want:
        err(f"docs/testing/cases.md: phase totals sentence {ms.groups()} differs from computed {want}")
else:
    err("docs/testing/cases.md: phase totals sentence not found")

# 11. parameter register and corpus files
reg = texts.get("docs/parameter-register.md", "")
sec1 = reg.split("## 1.")[1].split("## 2.")[0] if "## 1." in reg else ""
for row in re.findall(r"^\| (PAR-F-\d+) \|(.*)$", sec1, re.M):
    cells = [c.strip() for c in row[1].strip().strip("|").split("|")]
    if len(cells) < 4:
        err(f"parameter register {row[0]}: malformed row")
        continue
    pat = cells[2].strip("`")
    files_ = re.findall(r"`([^`]+)`", cells[3])
    for fl in files_:
        fp = ROOT / fl
        if not fp.exists():
            err(f"parameter register {row[0]}: file {fl} missing")
        elif not re.search(pat, fp.read_text(encoding="utf-8")):
            err(f"parameter register {row[0]}: pattern {pat!r} not found in {fl}")
sec2 = reg.split("## 2.")[1].split("## 3.")[0] if "## 2." in reg else ""
if cat:
    for c in cat["controls"]:
        if any("to be set" in prm for prm in c["parameters"]) and c["id"] not in sec2:
            err(f"parameter register: {c['id']} has 'to be set' parameters but is not named in Section 2")
for jl in sorted((ROOT / "tests" / "fixtures" / "corpus").glob("*.jsonl")):
    seen_ids = set()
    for n, line in enumerate(jl.read_text(encoding="utf-8").split("\n"), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            err(f"{jl.name}:{n}: invalid JSON")
            continue
        for key in ("id", "label", "category", "text"):
            if key not in obj:
                err(f"{jl.name}:{n}: missing field {key}")
        if obj.get("id") in seen_ids:
            err(f"{jl.name}:{n}: duplicate id {obj.get('id')}")
        seen_ids.add(obj.get("id"))
        allowed = {"benign", "poisoned"} if jl.name.startswith("tool_descriptions") else {"benign", "injected"}
        if obj.get("label") not in allowed:
            err(f"{jl.name}:{n}: label must be one of {sorted(allowed)}")


# 12. generated HTML is well-formed (balanced non-void tags)
from html.parser import HTMLParser  # noqa: E402

class _Balance(HTMLParser):
    VOID = {"meta", "br", "hr", "img", "input", "link"}

    def __init__(self):
        super().__init__()
        self.stack, self.problems = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.problems.append(f"unexpected </{tag}> (open: {self.stack[-3:]})")
        else:
            self.stack.pop()

if html_path.exists():
    bal = _Balance()
    bal.feed(html_path.read_text(encoding="utf-8"))
    for pr in bal.problems[:5]:
        err(f"Plan/functional-spec.html: {pr}")
    if bal.stack:
        err(f"Plan/functional-spec.html: unclosed tags {bal.stack[-5:]}")


# 13. documentation index must list every design document
index_text = texts.get("docs/index.md", "")
for f in DOC_FILES:
    if f.startswith(("Plan/", "docs/", "compliance/", "controls/")) and f != "docs/index.md":
        if f"`{f}`" not in index_text:
            err(f"docs/index.md does not list {f}")

# informational: placeholder inventory (never fails)
_verify = {f: len(re.findall(r"\[VERIFY", t)) for f, t in texts.items()}
_tbd = {f: len(re.findall(r"TBD", t)) for f, t in texts.items()}
placeholder_note = f"placeholders: [VERIFY] {sum(_verify.values())}, TBD {sum(_tbd.values())}"

if errors:
    print("FAILED:")
    for e in errors:
        print(" -", e)
    sys.exit(1)
print(
    f"OK ({placeholder_note}): {len(fr_defined)} FR, {len(nfr_defined)} NFR, {len(ac_defined)} AC, {len(set(catalogue))} TC; "
    f"versions {versions}"
)
