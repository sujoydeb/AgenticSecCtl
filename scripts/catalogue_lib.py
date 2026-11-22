"""Loader and renderer for controls/catalogue.yaml (stdlib only).

PyYAML is not assumed to be installed, so the catalogue is written in a strict
YAML subset that this module parses and rejects anything outside of it:

    version: "0.1"                      # top-level scalar (double-quoted string)
    excluded:                           # top-level list of double-quoted strings
      - "text"
    controls:                           # list of maps
      - id: "CTL-01"                    # scalar field (double-quoted string)
        how_it_works:                   # list field (double-quoted strings)
          - "step one"

Rules: two-space indentation, every value a single-line double-quoted string (an empty list is written []),
only the escapes \\" and \\\\, comments on their own line starting with '#'.
The file stays valid YAML, so a real YAML parser reads the same data.
"""
import re

SCALAR_FIELDS = [
    "id", "name", "objective", "enforcement", "type", "component",
    "failure_behavior", "residual_risk", "owner_role", "phase", "status", "verify",
]
LIST_FIELDS = [
    "how_it_works", "prevent", "detect", "respond", "recover", "parameters",
    "false_positives", "false_negatives", "bypass_scenarios", "requirements",
    "threats", "tests", "evidence", "metrics", "depends_on",
]
ENFORCEMENT = {"deterministic", "human", "advisory", "hybrid"}

_STR = r'"((?:[^"\\]|\\["\\])*)"'
_TOP_SCALAR = re.compile(r"^([a-z_]+): " + _STR + r"$")
_TOP_BLOCK = re.compile(r"^([a-z_]+):$")
_TOP_ITEM = re.compile(r"^  - " + _STR + r"$")
_CTRL_START = re.compile(r"^  - ([a-z_]+): " + _STR + r"$")
_CTRL_SCALAR = re.compile(r"^    ([a-z_]+): " + _STR + r"$")
_CTRL_BLOCK = re.compile(r"^    ([a-z_]+):$")
_CTRL_EMPTY = re.compile(r"^    ([a-z_]+): \[\]$")
_CTRL_ITEM = re.compile(r"^      - " + _STR + r"$")


def _unescape(s):
    return s.replace('\\"', '"').replace("\\\\", "\\")


class CatalogueError(Exception):
    pass


def load(path):
    """Parse the catalogue file into {'meta': {...}, 'lists': {...}, 'controls': [...]}."""
    meta, lists, controls = {}, {}, []
    cur_top = None      # name of the top-level block being filled
    cur_ctrl = None     # control dict being filled
    cur_field = None    # list field being filled inside a control
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    for n, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise CatalogueError(f"{path}:{n}: tabs are not allowed")
        if cur_top == "controls":
            m = _CTRL_START.match(raw)
            if m:
                cur_ctrl = {m.group(1): _unescape(m.group(2))}
                controls.append(cur_ctrl)
                cur_field = None
                continue
            m = _CTRL_SCALAR.match(raw)
            if m and cur_ctrl is not None:
                cur_ctrl[m.group(1)] = _unescape(m.group(2))
                cur_field = None
                continue
            m = _CTRL_EMPTY.match(raw)
            if m and cur_ctrl is not None:
                cur_ctrl[m.group(1)] = []
                cur_field = None
                continue
            m = _CTRL_BLOCK.match(raw)
            if m and cur_ctrl is not None:
                cur_field = m.group(1)
                cur_ctrl[cur_field] = []
                continue
            m = _CTRL_ITEM.match(raw)
            if m and cur_ctrl is not None and cur_field:
                cur_ctrl[cur_field].append(_unescape(m.group(1)))
                continue
            if not raw.startswith(" "):
                cur_top = None  # fall through to top-level handling
            else:
                raise CatalogueError(f"{path}:{n}: unsupported syntax in controls: {raw!r}")
        m = _TOP_SCALAR.match(raw)
        if m:
            meta[m.group(1)] = _unescape(m.group(2))
            cur_top = None
            continue
        m = _TOP_BLOCK.match(raw)
        if m:
            cur_top = m.group(1)
            if cur_top != "controls":
                lists[cur_top] = []
            cur_ctrl = cur_field = None
            continue
        m = _TOP_ITEM.match(raw)
        if m and cur_top and cur_top != "controls":
            lists[cur_top].append(_unescape(m.group(1)))
            continue
        raise CatalogueError(f"{path}:{n}: unsupported syntax: {raw!r}")
    return {"meta": meta, "lists": lists, "controls": controls}


def validate_structure(cat):
    """Return a list of structural problems (missing fields, bad enums, duplicates)."""
    problems = []
    seen = set()
    for c in cat["controls"]:
        cid = c.get("id", "<no id>")
        if cid in seen:
            problems.append(f"duplicate control id {cid}")
        seen.add(cid)
        if not re.fullmatch(r"CTL-\d{2}", cid):
            problems.append(f"{cid}: bad id format")
        for f in SCALAR_FIELDS:
            if f not in c or not isinstance(c[f], str):
                problems.append(f"{cid}: missing scalar field '{f}'")
            elif f != "verify" and not c[f].strip():
                problems.append(f"{cid}: empty field '{f}'")
        for f in LIST_FIELDS:
            if f not in c or not isinstance(c[f], list):
                problems.append(f"{cid}: missing list field '{f}'")
            elif f not in ("depends_on", "recover", "respond", "detect", "prevent") and not c[f]:
                problems.append(f"{cid}: empty list '{f}'")
        for f in c:
            if f not in SCALAR_FIELDS + LIST_FIELDS:
                problems.append(f"{cid}: unknown field '{f}'")
        if c.get("enforcement") not in ENFORCEMENT:
            problems.append(f"{cid}: enforcement must be one of {sorted(ENFORCEMENT)}")
        if c.get("status") != "specified":
            problems.append(f"{cid}: status must be 'specified' (nothing is implemented)")
        for f in ("prevent", "detect", "respond", "recover"):
            if isinstance(c.get(f), list) and not c[f]:
                problems.append(f"{cid}: '{f}' must say 'None' explicitly when not applicable")
    return problems


def expand_ids(entries):
    """Expand ID entries with ranges, e.g. FR-DRIFT-1..7 or TC-A1..A5, into individual IDs."""
    out = []
    for e in entries:
        m = re.fullmatch(r"(FR-[A-Z]+-)(\d+)\.\.(\d+)", e)
        if m:
            out += [f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
            continue
        m = re.fullmatch(r"(NFR-)(\d+)\.\.(\d+)", e)
        if m:
            out += [f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
            continue
        m = re.fullmatch(r"(TC-[A-Z])(\d+)\.\.[A-Z]?(\d+)", e)
        if m:
            out += [f"{m.group(1)}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
            continue
        out.append(e)
    return out


def _bullets(items):
    return "\n".join(f"- {i}" for i in items) if items else "- None"


def render_markdown(cat):
    meta, lists, controls = cat["meta"], cat["lists"], cat["controls"]
    o = []
    o.append("# Control Catalogue: AgenticSecCtl\n")
    o.append(
        "> **Generated file. Do not edit.** Source: `controls/catalogue.yaml`. "
        "Regenerate with `python3 -I scripts/build_catalogue_md.py controls/catalogue.yaml controls/catalogue.md`.\n"
    )
    o.append("| | |\n|---|---|")
    o.append(f"| Version | {meta.get('version', '?')} |")
    o.append(f"| Status | {meta.get('status_note', '')} |")
    o.append(f"| Depends on | {meta.get('depends_on_docs', '')} |")
    o.append(f"| Satisfies | {meta.get('satisfies', '')} |")
    o.append("")
    o.append("## How to read this catalogue\n")
    o.append(meta.get("intro", "") + "\n")
    o.append("**Enforcement classes**\n")
    o.append(_bullets(lists.get("enforcement_classes", [])) + "\n")
    o.append("**Out of scope for this catalogue**\n")
    o.append(_bullets(lists.get("excluded", [])) + "\n")
    o.append("## Summary\n")
    o.append("| ID | Control | Type | Enforcement | Component | Phase | Owner (role) |")
    o.append("|---|---|---|---|---|---|---|")
    for c in controls:
        o.append(
            f"| [{c['id']}](#{c['id'].lower()}) | {c['name']} | {c['type']} | {c['enforcement']} | "
            f"{c['component']} | {c['phase']} | {c['owner_role']} |"
        )
    o.append("")
    for c in controls:
        o.append(f"## {c['id']}\n")
        o.append(f"### {c['name']}\n")
        o.append(f"**Objective.** {c['objective']}\n")
        o.append(
            f"**Enforcement:** {c['enforcement']} · **Type:** {c['type']} · **Component:** {c['component']} · "
            f"**Phase:** {c['phase']} · **Owner (role):** {c['owner_role']} · **Status:** {c['status']}\n"
        )
        o.append("**How it works**\n")
        o.append("\n".join(f"{i}. {s}" for i, s in enumerate(c["how_it_works"], 1)) + "\n")
        o.append("**Prevent**\n\n" + _bullets(c["prevent"]) + "\n")
        o.append("**Detect**\n\n" + _bullets(c["detect"]) + "\n")
        o.append("**Respond**\n\n" + _bullets(c["respond"]) + "\n")
        o.append("**Recover**\n\n" + _bullets(c["recover"]) + "\n")
        o.append("**Parameters**\n\n" + _bullets(c["parameters"]) + "\n")
        o.append(f"**Failure behaviour.** {c['failure_behavior']}\n")
        o.append("**False positives**\n\n" + _bullets(c["false_positives"]) + "\n")
        o.append("**False negatives**\n\n" + _bullets(c["false_negatives"]) + "\n")
        o.append("**Bypass scenarios**\n\n" + _bullets(c["bypass_scenarios"]) + "\n")
        o.append(f"**Residual risk.** {c['residual_risk']}\n")
        o.append(f"**Requirements:** {', '.join(c['requirements'])}\n")
        o.append(f"**Threats:** {', '.join(c['threats'])}\n")
        o.append(f"**Tests:** {', '.join(c['tests'])}\n")
        if c["depends_on"]:
            o.append(f"**Depends on controls:** {', '.join(c['depends_on'])}\n")
        o.append("**Evidence required**\n\n" + _bullets(c["evidence"]) + "\n")
        o.append("**Metrics (KPI/KRI)**\n\n" + _bullets(c["metrics"]) + "\n")
        if c["verify"].strip():
            o.append(f"**Unverified claims.** {c['verify']}\n")
    return "\n".join(o).rstrip() + "\n"
