"""Scan one tool definition (FR-SCAN-1, FR-SCAN-2, CTL-02). Pure function: no network, no files, no clock.

Same input and same rule set give the same findings in the same order and the same score. The scanner never
fetches a URL it finds (TC-A3): it only reads the text.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from . import normalise as nm
from .classifier import Classifier
from .rules import (
    RANK, RULESET_VERSION, Finding, evidence, finding, match_instruction_rules, max_severity, risk_score, ruleset_hash,
)

MAX_DEPTH, MAX_STRINGS, MAX_FINDINGS = 24, 5000, 100
_URL = re.compile(r"(?i)\b(?:https?|ftp|file|gopher)://[^\s'\"<>)\]]+")
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
_DOC_CONTEXT = re.compile(r"\b(documentation|docs?|see|reference|manual|guide|api|wiki|site|page|homepage|readme|spec(?:ification)?|more information|details|endpoint)\b")
_DATA_FIELDS = {"default", "examples", "example", "enum", "const"}
_FIELD_NAMES = re.compile(r"^(system_?prompt|instructions?|side_?note|note_?to_?(ai|assistant|model|llm)|assistant_?instructions?|hidden_?(note|instruction)s?|override)$", re.I)
MAX_LONG_DEFAULT = 200
MAX_TEXT = 4000


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    risk_score: float
    max_severity: str
    rule_set_version: str
    rule_set_hash: str

    @property
    def blocking(self) -> bool:
        """A Critical finding blocks approval except through the two-approver override (FR-SCAN-4)."""
        return any(f.severity == "critical" for f in self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {"risk_score": self.risk_score, "max_severity": self.max_severity, "rule_set": {"version": self.rule_set_version, "hash": self.rule_set_hash},
                "findings": [f.as_dict() for f in self.findings]}


def _walk(node: Any, path: str, out: list[tuple[str, str, bool]], depth: int = 0) -> bool:
    """Collect (location, string, is_data_field). Returns False if a limit cut the walk short."""
    if depth > MAX_DEPTH or len(out) >= MAX_STRINGS:
        return False
    ok = True
    if isinstance(node, str):
        leaf = path.rsplit(".", 1)[-1].split("[")[0]
        out.append((path or "tool", node, leaf in _DATA_FIELDS or any(f".{d}" in path for d in _DATA_FIELDS)))
    elif isinstance(node, dict):
        for k, v in node.items():
            sub = f"{path}.{k}" if path else str(k)
            if isinstance(k, str) and k:
                if path.endswith("properties") or path.endswith("$defs") or path.endswith("definitions"):
                    out.append((sub + " (name)", k, False))
            ok = _walk(v, sub, out, depth + 1) and ok
    elif isinstance(node, list):
        for i, v in enumerate(node):
            ok = _walk(v, f"{path}[{i}]", out, depth + 1) and ok
    return ok


def _hidden_findings(nv: nm.Normalised, loc: str) -> list[Finding]:
    out: list[Finding] = []
    kinds: dict[str, list[nm.Hidden]] = {}
    for h in nv.hidden:
        kinds.setdefault(h.kind, []).append(h)
    offsets = lambda hs: "offsets " + ",".join(str(h.offset) for h in hs[:12]) + ("..." if len(hs) > 12 else "")  # noqa: E731
    if "tag" in kinds:
        out.append(finding("R-HIDDEN-UNICODE", loc, evidence(f"{len(kinds['tag'])} tag characters at {offsets(kinds['tag'])}; decoded: {nv.hidden_tag_text}")))
    if "bidi" in kinds:
        out.append(finding("R-BIDI-CONTROL", loc, evidence(f"{len(kinds['bidi'])} bidirectional control characters at {offsets(kinds['bidi'])}")))
    if "zero-width" in kinds:
        out.append(finding("R-ZERO-WIDTH", loc, evidence(f"{len(kinds['zero-width'])} zero-width characters at {offsets(kinds['zero-width'])}")))
    if "format" in kinds:
        out.append(finding("R-FORMAT-CHAR", loc, evidence(f"{len(kinds['format'])} invisible format characters at {offsets(kinds['format'])}")))
    return out


def _urls(nv: nm.Normalised, loc: str, is_data: bool) -> list[Finding]:
    out: list[Finding] = []
    text, skel = nv.text, nv.skeleton
    for m in list(_URL.finditer(text))[:20]:
        if is_data:
            out.append(finding("R-URL-IN-DATA", loc, evidence(text, m.start(), m.end())))
            continue
        ctx = skel[max(0, m.start() - 80):m.end() + 40]
        out.append(finding("R-URL-REFERENCE" if _DOC_CONTEXT.search(ctx) else "R-URL-UNEXPLAINED", loc, evidence(text, m.start(), m.end())))
    for m in list(_IP.finditer(text))[:20]:
        try:
            ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        out.append(finding("R-IP-LITERAL", loc, evidence(text, m.start(), m.end())))
    return out


def _scan_text(text: str, loc: str, is_data: bool, depth: int = 0) -> list[Finding]:
    nv = nm.normalise(text)
    out: list[Finding] = _hidden_findings(nv, loc)
    out += match_instruction_rules(nv.skeleton, loc)
    out += _urls(nv, loc, is_data)
    if nv.mixed_script_words:
        out.append(finding("R-HOMOGLYPH", loc, evidence("mixed-script words: " + ", ".join(nv.mixed_script_words[:5]))))
    if len(text) > MAX_TEXT or nv.truncated:
        out.append(finding("R-OVERSIZE", loc, evidence(f"{len(text)} characters" + ("; scanned head and tail only" if nv.truncated else ""))))
    if is_data and len(nv.text) > MAX_LONG_DEFAULT:
        out.append(finding("R-SCHEMA-LONG-DEFAULT", loc, evidence(f"{len(nv.text)} characters in a data field")))
    # text a reviewer cannot see: decoded tag characters and right-to-left overridden segments
    for label, hidden_text in [("hidden text", nv.hidden_tag_text)] + [("mirrored text", s) for s in nv.reversed_segments]:
        if not hidden_text.strip():
            continue
        hits = match_instruction_rules(nm.skeleton_of(hidden_text), f"{loc} ({label})")
        if hits:
            out += hits
            out.append(finding("R-HIDDEN-INSTRUCTION", loc, evidence(f"{label}: {hidden_text}")))
    # encoded blobs: decode a few layers and look for instructions inside
    if depth < nm.MAX_DECODE_DEPTH:
        for blob in nv.blobs:
            inner = _scan_text(blob.decoded, f"{loc} ({blob.kind} blob)", False, depth + 1)
            if any(RANK[f.severity] >= RANK["high"] for f in inner) or any(f.rule_id == "R-ENCODED-INSTRUCTION" for f in inner):
                out.append(finding("R-ENCODED-INSTRUCTION", loc, evidence(f"{blob.kind} blob decodes to: {blob.decoded}")))
                out += [f for f in inner if RANK[f.severity] >= RANK["high"]]
            else:
                out.append(finding("R-ENCODED-BLOB", loc, evidence(f"{blob.kind} blob decodes to: {blob.decoded}")))
    return out


def _structure(tool: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    def visit(node: Any, path: str, depth: int) -> None:
        if depth > MAX_DEPTH or not isinstance(node, dict):
            return
        props = node.get("properties")
        if isinstance(props, dict):
            for name, sub in list(props.items())[:500]:
                if isinstance(name, str) and _FIELD_NAMES.match(name):
                    out.append(finding("R-SCHEMA-FIELD-NAME", f"{path}.properties.{name}", evidence(f"property named {name!r}")))
                visit(sub, f"{path}.properties.{name}", depth + 1)
        for key in ("items", "additionalProperties"):
            visit(node.get(key), f"{path}.{key}", depth + 1)
    for key in ("inputSchema", "outputSchema"):
        visit(tool.get(key), key, 0)
    return out


def scan_tool(tool: dict[str, Any], *, classifier: Classifier | None = None) -> ScanResult:
    strings: list[tuple[str, str, bool]] = []
    complete = _walk(tool, "", strings)
    found: list[Finding] = []
    for loc, text, is_data in strings:
        found += _scan_text(text, loc, is_data)
    found += _structure(tool)
    if not complete:
        found.append(finding("R-OVERSIZE", "tool", evidence("definition deeper or larger than the scan limits; not fully scanned")))
    if classifier is not None:
        try:
            joined = " ".join(t for _, t, d in strings if not d)[:8000]
            score = float(classifier.classify(joined))
            if 0.8 <= score <= 1.0:
                found.append(finding("R-CLASSIFIER", "description", evidence(f"advisory score {score:.2f}")))
        except Exception:  # noqa: BLE001 - an advisory component must never change the deterministic outcome
            pass
    unique: dict[tuple[str, str, str], Finding] = {}
    for f in found:
        unique.setdefault((f.rule_id, f.location, f.evidence), f)
    ordered = sorted(unique.values(), key=lambda f: (-RANK[f.severity], f.rule_id, f.location, f.evidence))[:MAX_FINDINGS]
    return ScanResult(tuple(ordered), risk_score(ordered), max_severity(ordered), RULESET_VERSION, ruleset_hash())
