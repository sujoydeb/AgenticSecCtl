"""WP-1.7: the labelled corpus against the scanner (FR-SCAN-1/2; corpus rules in docs/testing/fixtures-and-corpora.md).

The development set is the set the rules were written against, so this is a regression gate: it must not get worse.
It is NOT evidence of quality. The held-out and evasion sets are deliberately not asserted here (that would turn
them into tuning targets); `scripts/measure_scanner.py` reports them, and the saved results record the numbers.
"""
import json
import pathlib
import unittest

from agenticsecctl_scanner.rules import RANK
from agenticsecctl_scanner.scan import scan_tool

CORPUS = pathlib.Path(__file__).resolve().parents[3] / "tests/fixtures/corpus"


def load(name):
    return [json.loads(line) for line in (CORPUS / name).read_text().splitlines() if line.strip()]


class Development(unittest.TestCase):
    rows = load("tool_descriptions.jsonl")

    def test_every_poisoned_sample_reaches_its_expected_severity(self):
        for r in self.rows:
            if r["label"] != "poisoned":
                continue
            sev = scan_tool({"name": "t", "description": r["text"]}).max_severity
            self.assertGreaterEqual(RANK[sev], RANK[r["expected_min_severity"]], f"{r['id']} {r['category']}: got {sev}")

    def test_no_benign_sample_is_flagged_medium_or_higher(self):
        for r in self.rows:
            if r["label"] == "benign":
                sev = scan_tool({"name": "t", "description": r["text"]}).max_severity
                self.assertLess(RANK[sev], RANK["medium"], f"{r['id']} ({r['category']}) flagged {sev}: {r['text'][:80]}")

    def test_hard_negatives_are_present_so_the_check_above_means_something(self):
        self.assertGreaterEqual(sum(r["category"] == "hard_negative" for r in self.rows), 6)


class OtherSetsAreWellFormedButNotAsserted(unittest.TestCase):
    def test_files(self):
        for name in ("tool_descriptions_holdout.jsonl", "tool_descriptions_evasion.jsonl"):
            rows = load(name)
            self.assertGreaterEqual(len(rows), 16)
            self.assertEqual(len({r["id"] for r in rows}), len(rows))
            for r in rows:
                self.assertIn(r["label"], ("benign", "poisoned"))
                self.assertIn(r["expected_min_severity"], ("none", "low", "medium", "high", "critical"))
                scan_tool({"name": "t", "description": r["text"]})  # must not raise

    def test_held_out_samples_are_not_in_the_development_set(self):
        dev = {r["text"] for r in load("tool_descriptions.jsonl")}
        for name in ("tool_descriptions_holdout.jsonl", "tool_descriptions_evasion.jsonl"):
            self.assertFalse(dev & {r["text"] for r in load(name)})


if __name__ == "__main__":
    unittest.main()
