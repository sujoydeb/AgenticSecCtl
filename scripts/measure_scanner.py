#!/usr/bin/env python3
"""Measure the scanner on a labelled corpus and print a Markdown report (WP-1.7, spec Section 10, corpus Section 3.5).

    python3 scripts/measure_scanner.py [--set dev|holdout|both] [--details]

Definitions (stated so the numbers can be checked):
* A sample is *flagged* when the scan's highest severity is medium or higher. Low findings (for example a
  documentation link) do not count as a flag.
* A poisoned sample is a true positive when it is flagged AND its highest severity reaches the sample's
  ``expected_min_severity`` (for an expected "low" any finding counts); otherwise it is a false negative.
* A benign sample that is flagged is a false positive.
* Precision = TP / (TP + FP); recall = TP / (TP + FN). Wilson 95 percent intervals are shown; with fewer than
  100 samples per class the result is indicative only.
The development set is the set the rules were written against, so its numbers are optimistic. The held-out set was
committed before any rule existed and has never been used for tuning, but it was written by the same author as the
rules, so it shares their assumptions. The evasion set is written to get around the rules (paraphrase, other
languages, leetspeak, other encodings); its recall is expected to be low and is the honest picture of adaptive attackers.
It has no benign samples, so precision is not defined for it.
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "services/common/src"), str(ROOT / "services/scanner/src")]
from agenticsecctl_scanner.rules import RANK, RULESET_VERSION, ruleset_hash  # noqa: E402
from agenticsecctl_scanner.scan import scan_tool  # noqa: E402

FILES = {"dev": "tool_descriptions.jsonl", "holdout": "tool_descriptions_holdout.jsonl", "evasion": "tool_descriptions_evasion.jsonl"}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - m) / d, (c + m) / d)


def run(name: str, details: bool) -> list[str]:
    rows = [json.loads(line) for line in (ROOT / "tests/fixtures/corpus" / FILES[name]).read_text().splitlines() if line.strip()]
    tp = fp = fn = tn = 0
    miss, false_pos, per_cat = [], [], {}
    for r in rows:
        res = scan_tool({"name": "t", "description": r["text"]})
        flagged = RANK.get(res.max_severity, 0) >= RANK["medium"]
        if r["label"] == "poisoned":
            need = RANK.get(r["expected_min_severity"], 2)
            hit = flagged and RANK.get(res.max_severity, 0) >= need or (need <= RANK["low"] and RANK.get(res.max_severity, 0) >= need)
            tp += hit
            fn += not hit
            per_cat.setdefault(r["category"], [0, 0])
            per_cat[r["category"]][0] += hit
            per_cat[r["category"]][1] += 1
            if not hit:
                miss.append((r["id"], r["category"], r["expected_min_severity"], res.max_severity, r["text"]))
        else:
            fp += flagged
            tn += not flagged
            if flagged:
                false_pos.append((r["id"], res.max_severity, [f.rule_id for f in res.findings][:4], r["text"]))
    P, R = (tp / (tp + fp) if tp + fp else float("nan")), (tp / (tp + fn) if tp + fn else float("nan"))
    plo, phi, rlo, rhi = (*wilson(tp, tp + fp), *wilson(tp, tp + fn))
    n_pos, n_neg = tp + fn, fp + tn
    out = [f"### {name} set ({FILES[name]}): {n_pos} poisoned, {n_neg} benign", "",
           "| Measure | Value | 95% interval | Target (spec Section 10) |", "|---|---|---|---|",
           f"| Recall | {R:.1%} ({tp} of {n_pos}) | {rlo:.1%} to {rhi:.1%} | at least 95% |",
           f"| Precision | {P:.1%} ({tp} of {tp + fp}) | {plo:.1%} to {phi:.1%} | at least 90% |",
           f"| False positives | {fp} of {n_neg} benign | | |", ""]
    out += ["Per category (recall): " + ", ".join(f"{c} {a}/{b}" for c, (a, b) in sorted(per_cat.items())), ""]
    if miss:
        out += ["Missed:", *[f"- {i} ({c}; expected {e}, got {g}): {t[:110]!r}" for i, c, e, g, t in miss], ""]
    if false_pos:
        out += ["False positives:", *[f"- {i} ({s}; {rr}): {t[:110]!r}" for i, s, rr, t in false_pos], ""]
    if details:
        out += ["(details printed above)"]
    return out


if __name__ == "__main__":
    which = sys.argv[sys.argv.index("--set") + 1] if "--set" in sys.argv else "both"
    sets = ["dev", "holdout", "evasion"] if which == "both" else [which]
    print(f"# Scanner measurement, rule set {RULESET_VERSION} ({ruleset_hash()[:16]}...)\n")
    for s in sets:
        print("\n".join(run(s, "--details" in sys.argv)))
