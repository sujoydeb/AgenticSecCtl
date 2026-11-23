"""Deterministic scanner rules (FR-SCAN-1, FR-SCAN-2, CTL-02).

Each rule has a fixed ID, severity and confidence. Findings carry rule ID, severity, location (a path into the
tool definition), a short escaped evidence excerpt and the confidence. The risk score is reproducible:
``min(100, sum(weight[severity] * confidence))`` over distinct findings, with weights Critical 40, High 20,
Medium 8, Low 2 (specification Section 4.6). The rule set has a version and a content hash; any change to a
pattern, severity or confidence changes the hash, and every scan stores both.

The rules are heuristics over untrusted text. They are known to miss paraphrase, other languages and
instructions that never name an action; the corpus baseline reports how much (Section "Limits" of the
results). They never decide alone to *allow* anything.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from agenticsecctl_common.canonical import canonicalize
from agenticsecctl_common.contracts import SEVERITY_WEIGHTS
from agenticsecctl_common.redact import escape_untrusted, redact

RULESET_VERSION = "scan-rules-1"
WEIGHTS = dict(SEVERITY_WEIGHTS)  # one definition, in common
RANK = {"none": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
EVIDENCE_CHARS = 200


@dataclass(frozen=True)
class PatternRule:
    id: str
    severity: str
    confidence: float
    title: str
    patterns: tuple[str, ...]
    guard_negation: bool = False

    def compiled(self) -> tuple[re.Pattern[str], ...]:
        return tuple(re.compile(p) for p in self.patterns)


_NEG = re.compile(r"\b(never|not|no|without|doesn'?t|does not|don'?t|do not|cannot|can'?t|won'?t|will not|isn'?t|is not)\b")
_REQUIREMENT = re.compile(r"\b(must|always|need|needs|required?|requires|should|before|first|has to|have to)\b")

# Instruction-like rules, run on the visible text, on decoded hidden text and on decoded blobs.
INSTRUCTION_RULES: tuple[PatternRule, ...] = (
    PatternRule("R-OVERRIDE", "critical", 0.9, "Override of earlier instructions or role", (
        r"\b(ignore|disregard|forget|override|bypass|discard|neglect)\b.{0,50}\b(previous|prior|earlier|above|preceding|all|any|your|the|these)\b.{0,40}\b(instructions?|rules?|guidelines?|prompts?|directives?|polic(?:y|ies)|guidance|constraints|restrictions|safeguards)\b",
        r"\b(ignore|disregard|forget|override|reveal|print|repeat|leak|bypass)\b.{0,40}\b(system|developer|hidden|initial) (prompt|message|instructions?)\b",
        r"<\s*/?\s*(important|system|instructions?|admin|override)\s*>", r"\[\s*(system|admin|override)\s*\]",
        r"\bnote to (the )?(assistant|ai|model|llm|agent)\b", r"\bnew instructions?\s*:", r"\byou are now\b.{0,40}\b(mode|unrestricted|free|allowed)\b",
        r"\b(from now on|henceforth)\b.{0,60}\b(ignore|obey|follow|no longer|only)\b", r"\b(maintenance|developer|debug|admin|god) mode\b",
        r"\bact as (an? )?(unrestricted|unfiltered|jailbroken)\b", r"\bapprove (every|all|any) (request|call|action)s?\b",
        r"\bobey\b.{0,30}\b(tool|output|response|result|notes)\b",
    )),
    PatternRule("R-CONCEAL", "high", 0.85, "Instruction to hide behaviour from the user", (
        r"\b(do not|don'?t|never|must not|should not|shall not|avoid|without)\b.{0,30}\b(tell|inform|mention|reveal|notify|disclose|alert|show|let)\b.{0,40}\b(the )?(user|human|operator|customer|owner|anyone|that|this)\b",
        r"\b(user|human|operator|customer)\b.{0,25}\b(must|should|shall|is to|are to) not be (told|informed|notified|made aware|aware|shown)\b",
        r"\b(secretly|quietly|silently|covertly|invisibly|stealthily|discreetly)\b", r"\bhidden (recipient|participant|copy|field|parameter|argument|bcc)\b",
        r"\bkeep (this|it|that) (a )?(secret|hidden|between)\b",
    )),
    PatternRule("R-CRED-REQUEST", "critical", 0.85, "Request for credentials or secrets", (
        r"~/\.ssh|\bid_(rsa|ed25519|ecdsa|dsa)\b|/etc/(passwd|shadow)|\.aws/credentials|\.netrc\b|(^|[\s'\"(/])\.env\b|\bcredentials? file\b|\bprivate key file\b",
        r"\b(include|pass|send|provide|supply|attach|put|add|append|forward|paste|enter|submit|read|open|cat|copy|upload)\b.{0,60}\b(passwords?|passwd|credentials?|api[ _-]?keys?|access keys?|secrets?|tokens?|private keys?|session (?:cookie|token|id)s?|cookies?)\b",
        r"\b(passwords?|passwd|credentials?|api[ _-]?keys?|access keys?|secrets?|tokens?|private keys?)\b.{0,50}\b(must|needs? to|should|has to|have to|is to) be (included|passed|sent|provided|supplied|attached|entered|submitted|forwarded)\b",
        r"\b(needs?|requires?|must (?:have|receive)|wants?)\b.{0,50}\b(contents? of|copy of|a copy of|access to)?.{0,40}\b(credentials?|passwords?|private keys?|api[ _-]?keys?|secrets?|tokens?)\b",
    ), guard_negation=True),
    PatternRule("R-EXFIL-INSTRUCTION", "high", 0.85, "Instruction to send data to a destination", (
        r"\b(send|post|upload|forward|email|mail|transmit|leak|copy|mirror|exfiltrate|submit|relay|report)\b.{0,70}\b(to|at|into|via)\b.{0,50}(https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(attacker|collector|remote server|external server|third[- ]party|the caller|the vendor|vendor|webhook|pastebin)\b)",
        r"\b(upload|send|post|forward|exfiltrate|leak)s?\b.{0,40}\b(the )?(full |entire |whole )?(conversation|chat history|context|session|secrets?|credentials?|keys?|tokens?)\b.{0,30}\b(to|at)\b",
    )),
    PatternRule("R-CROSS-TOOL", "high", 0.8, "Instruction about how other tools are used", (
        r"\b(first|always|before)\b.{0,30}\b(call|use|invoke|run|execute)\b.{0,20}\bthis (tool|function)\b",
        r"\b(instead of|rather than|in place of)\b.{0,40}\b(tool|function)\b",
        r"\b(when|whenever|if)\b.{0,30}\b(tool|function)\b.{0,20}\b(is|are|gets?) (used|called|invoked|run|executed)\b",
        r"\balways (call|use|invoke|prefer|choose) this (tool|function)\b", r"\bprefer this (tool|function) over\b",
        r"\bforward (the |all |every )?(arguments?|inputs?|parameters?|requests?|whatever)\b",
        r"\b(add|include|insert)\b.{0,25}\bas (a )?hidden (recipient|participant|copy)\b",
    )),
    PatternRule("R-NO-CONFIRM", "medium", 0.7, "Action without asking the user", (
        r"\bwithout (asking|confirmation|confirming|approval|consulting|permission|prompting)\b", r"\bdisable (all )?(confirmations?|approvals?|safety|logging|guardrails?|warnings?)\b",
    )),
    PatternRule("R-DELEGATED-INSTRUCTION", "medium", 0.7, "Follow instructions that arrive in tool output", (
        r"\b(carry out|follow|execute|obey|perform|apply)\b.{0,40}\b(step|instructions?|commands?|directions?|notes?)\b.{0,60}\b(returned|contained|provided|given|in the (output|response|error|result)|from (this|the) (tool|server))\b",
        r"\b(error|failure|response|output) (text|message)\b.{0,40}\b(will )?contain.{0,30}\b(next step|instructions?|command)\b",
        r"\bfollow only the (notes|instructions|steps)\b",
    )),
    PatternRule("R-ROLE-MARKER", "medium", 0.6, "Role marker inside a data field", (
        r"(^|[.'\"]\s*)(assistant|system|developer)\s*:\s", r"\b(open|call|use) the \w+ tool and (disable|ignore|skip|bypass|delete)\b",
    )),
    PatternRule("R-TRUST-CLAIM", "high", 0.7, "Claim of special trust or authority", (
        r"\b(must|should|has to|needs to) be trusted\b", r"\btrusted with (all|every|any)\b", r"\b(grant|give)\b.{0,20}\b(full|admin|unrestricted|root) (access|trust|rights|permissions)\b",
        r"\bthe organi[sz]ation'?s? (security|admin|official) (tool|agent|service)\b",
    )),
    PatternRule("R-PATH-TRAVERSAL", "medium", 0.7, "Path traversal or local file reference", (
        r"(^|[\s'\"=(/])\.\./|\.\.\\", r"\bfile:///", r"\bpath may be \.\./",
    )),
    PatternRule("R-SCHEMA-ANOMALY", "medium", 0.6, "Unrestricted input described", (
        r"\b(any value|arbitrary (command|code|sql|script|input|statement|value)s?|unrestricted|unvalidated)\b", r"additionalproperties\s*:\s*true",
    )),
)
INSTRUCTION_BY_ID = {r.id: r for r in INSTRUCTION_RULES}
_COMPILED = {r.id: r.compiled() for r in INSTRUCTION_RULES}

# Rules implemented in code (not by pattern list). Listed so the rule-set hash covers their severity and confidence.
CODE_RULES = (
    ("R-HIDDEN-UNICODE", "critical", 1.0, "Unicode tag characters carry hidden text"),
    ("R-HIDDEN-INSTRUCTION", "critical", 1.0, "Hidden or mirrored text contains an instruction"),
    ("R-BIDI-CONTROL", "high", 0.9, "Bidirectional override or isolate characters"),
    ("R-ZERO-WIDTH", "medium", 0.8, "Zero-width characters in a description"),
    ("R-FORMAT-CHAR", "low", 0.4, "Other invisible format characters"),
    ("R-ENCODED-BLOB", "medium", 0.7, "Encoded text blob"),
    ("R-ENCODED-INSTRUCTION", "critical", 0.9, "Encoded blob decodes to an instruction"),
    ("R-HOMOGLYPH", "medium", 0.8, "Word mixes Latin with look-alike letters"),
    ("R-IP-LITERAL", "high", 0.9, "IP address literal"),
    ("R-URL-UNEXPLAINED", "high", 0.7, "URL without a documentation context"),
    ("R-URL-REFERENCE", "low", 0.5, "URL given as documentation"),
    ("R-URL-IN-DATA", "high", 0.8, "URL in a schema default, example or enum"),
    ("R-SCHEMA-FIELD-NAME", "medium", 0.6, "Schema field named like an instruction channel"),
    ("R-SCHEMA-LONG-DEFAULT", "medium", 0.6, "Long text in a schema default or enum"),
    ("R-OVERSIZE", "low", 0.6, "Very long text field"),
    ("R-CLASSIFIER", "medium", 0.5, "Advisory classifier signal (never lowers or approves)"),
)
CODE_META = {i: (sev, conf, title) for i, sev, conf, title in CODE_RULES}


def ruleset_hash() -> str:
    doc = {"version": RULESET_VERSION, "weights": WEIGHTS,
           "pattern_rules": [{"id": r.id, "severity": r.severity, "confidence": r.confidence, "patterns": list(r.patterns),
                              "guard_negation": r.guard_negation} for r in INSTRUCTION_RULES],
           "code_rules": [list(r) for r in CODE_RULES]}
    return hashlib.sha256(canonicalize(doc)).hexdigest()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    location: str
    evidence: str
    confidence: float

    def as_dict(self) -> dict[str, object]:
        return {"rule_id": self.rule_id, "severity": self.severity, "location": self.location,
                "evidence": self.evidence, "confidence": self.confidence}


def evidence(text: str, start: int = 0, end: int | None = None, prefix: str = "") -> str:
    end = len(text) if end is None else end
    lo, hi = max(0, start - 40), min(len(text), end + 60)
    return escape_untrusted(redact(prefix + text[lo:hi]), EVIDENCE_CHARS)


def finding(rule_id: str, location: str, ev: str) -> Finding:
    if rule_id in INSTRUCTION_BY_ID:
        r = INSTRUCTION_BY_ID[rule_id]
        return Finding(rule_id, r.severity, location, ev, r.confidence)
    sev, conf, _ = CODE_META[rule_id]
    return Finding(rule_id, sev, location, ev, conf)


_SENT = re.compile(r"(?<=[.!?;])\s+|\n+")


CHUNK, OVERLAP, MAX_CHUNKS = 4000, 300, 600


def _chunks(skeleton: str):
    """Sentences, with any long run (no full stop for thousands of characters) cut into overlapping pieces so an
    instruction placed late in a run-on text is still scanned; the overlap keeps a phrase from falling in the gap."""
    count = 0
    for sentence in _SENT.split(skeleton):
        if not sentence:
            continue
        for start in range(0, len(sentence), CHUNK - OVERLAP):
            yield sentence[start:start + CHUNK]
            count += 1
            if count >= MAX_CHUNKS or start + CHUNK >= len(sentence):
                break
        if count >= MAX_CHUNKS:
            return


def match_instruction_rules(skeleton: str, location: str, *, only: set[str] | None = None) -> list[Finding]:
    """Run the pattern rules sentence by sentence (keeps ``.{0,n}`` spans local and matching time bounded)."""
    out: list[Finding] = []
    seen: set[str] = set()
    for sentence in _chunks(skeleton):
        for rule in INSTRUCTION_RULES:
            if rule.id in seen or (only is not None and rule.id not in only):
                continue
            for pat in _COMPILED[rule.id]:
                m = pat.search(sentence)
                if not m:
                    continue
                if rule.guard_negation:
                    before = sentence[max(0, m.start() - 30):m.start() + 12]
                    if _NEG.search(before) and not _REQUIREMENT.search(sentence):
                        continue
                seen.add(rule.id)
                out.append(finding(rule.id, location, evidence(sentence, m.start(), m.end())))
                break
    return out


def risk_score(findings: list[Finding]) -> float:
    return round(min(100.0, sum(WEIGHTS[f.severity] * f.confidence for f in findings)), 2)


def max_severity(findings: list[Finding]) -> str:
    return max((f.severity for f in findings), key=lambda s: RANK[s], default="none") if findings else "none"


def describe_rules() -> str:
    return json.dumps({"version": RULESET_VERSION, "hash": ruleset_hash(),
                       "rules": [r.id for r in INSTRUCTION_RULES] + [r[0] for r in CODE_RULES]})
