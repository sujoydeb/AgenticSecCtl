"""WP-1.4 tests: audit chain, verifier (TC-Z6 chain part) and decision replay (TC-Z20)."""
import copy
import threading
import unittest

from agenticsecctl_common.auditchain import (
    GENESIS_HASH,
    ChainWriter,
    EventError,
    compute_hash,
    verify_chain,
)
from agenticsecctl_common.replay import input_digest, replay_decisions


def _ev(i, tenant="t1", **kw):
    e = {"event_id": f"e{i}", "occurred_at": "2026-11-23T10:00:00Z",
         "event_type": "authz.allow", "actor": "agent-1", "subject_type": "tool",
         "subject_id": f"tool-{i}", "decision": "allow",
         "policy_hash": "p" * 64, "input_digest": "d" * 64}
    e.update(kw)
    return e


def _chain(n, tenant="t1"):
    w = ChainWriter()
    return [w.append(tenant, _ev(i)) for i in range(n)]


class ChainBasics(unittest.TestCase):
    def test_sequence_and_links(self):
        rows = _chain(5)
        self.assertEqual([r["seq"] for r in rows], [1, 2, 3, 4, 5])
        self.assertEqual(rows[0]["prev_hash"], GENESIS_HASH)
        for a, b in zip(rows, rows[1:], strict=False):
            self.assertEqual(b["prev_hash"], a["hash"])
        self.assertTrue(verify_chain(rows).ok)

    def test_hash_formula(self):
        r = _chain(1)[0]
        self.assertEqual(r["hash"], compute_hash(r["prev_hash"], {k: v for k, v in r.items()
                                                                 if k not in ("hash", "prev_hash")}))

    def test_tenants_have_independent_chains(self):
        w = ChainWriter()
        a = w.append("t1", _ev(1)); b = w.append("t2", _ev(2))
        self.assertEqual((a["seq"], b["seq"]), (1, 1))
        self.assertEqual(b["prev_hash"], GENESIS_HASH)

    def test_rejects_malformed_events(self):
        w = ChainWriter()
        for bad in ({}, _ev(1, event_type=""), _ev(1, event_type="not.in.vocab"),
                    {**_ev(1), "seq": 9}, {**_ev(1), "hash": "x"}):
            with self.assertRaises(EventError):
                w.append("t1", bad)

    def test_excerpt_is_redacted_and_bounded(self):
        w = ChainWriter()
        r = w.append("t1", _ev(1, redacted_excerpt="Bearer abc.def.ghi " + "x" * 1000))
        self.assertNotIn("abc.def", r["redacted_excerpt"])
        self.assertLessEqual(len(r["redacted_excerpt"]), 256)

    def test_secret_payload_keys_never_stored(self):
        w = ChainWriter()
        with self.assertRaises(EventError):
            w.append("t1", _ev(1, payload={"x": 1}))  # unknown field


class Idempotence(unittest.TestCase):
    def test_resubmitted_batch_adds_nothing(self):
        w = ChainWriter()
        batch = [_ev(i) for i in range(5)]
        first = w.append_batch("t1", batch)
        again = w.append_batch("t1", copy.deepcopy(batch))
        self.assertEqual(len(w.rows("t1")), 5)
        self.assertEqual(first, again)

    def test_same_event_id_different_content_is_rejected(self):
        w = ChainWriter()
        w.append("t1", _ev(1))
        with self.assertRaises(EventError):
            w.append("t1", _ev(1, decision="deny"))

    def test_same_event_id_other_tenant_is_separate(self):
        w = ChainWriter()
        w.append("t1", _ev(1)); w.append("t2", _ev(1))
        self.assertEqual(len(w.rows("t2")), 1)


class Concurrency(unittest.TestCase):
    def test_concurrent_writers_gap_free(self):
        w = ChainWriter()
        def work(k):
            for j in range(50):
                w.append("t1", _ev(k * 1000 + j))
        ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        rows = w.rows("t1")
        self.assertEqual([r["seq"] for r in rows], list(range(1, 401)))
        self.assertTrue(verify_chain(rows).ok)


class Tamper(unittest.TestCase):
    def setUp(self):
        self.rows = _chain(1000)

    def test_modified_row(self):
        rows = copy.deepcopy(self.rows)
        rows[499]["decision"] = "deny"
        r = verify_chain(rows)
        self.assertFalse(r.ok)
        self.assertEqual((r.first_bad_seq, r.kind), (500, "modified"))

    def test_modified_row_with_recomputed_own_hash_breaks_next_link(self):
        rows = copy.deepcopy(self.rows)
        rows[99]["decision"] = "deny"
        body = {k: v for k, v in rows[99].items() if k not in ("hash", "prev_hash")}
        rows[99]["hash"] = compute_hash(rows[99]["prev_hash"], body)
        r = verify_chain(rows)
        self.assertEqual((r.first_bad_seq, r.kind), (101, "modified"))

    def test_deleted_row(self):
        rows = copy.deepcopy(self.rows)
        del rows[299]
        r = verify_chain(rows)
        self.assertEqual((r.first_bad_seq, r.kind), (300, "deleted"))

    def test_deleted_first_row(self):
        r = verify_chain(copy.deepcopy(self.rows)[1:])
        self.assertEqual((r.first_bad_seq, r.kind), (1, "deleted"))

    def test_reordered_rows(self):
        rows = copy.deepcopy(self.rows)
        rows[199], rows[200] = rows[200], rows[199]
        r = verify_chain(rows)
        self.assertFalse(r.ok)
        self.assertEqual(r.first_bad_seq, 200)
        self.assertEqual(r.kind, "reordered")

    def test_duplicated_row(self):
        rows = copy.deepcopy(self.rows)
        rows.insert(11, copy.deepcopy(rows[10]))
        r = verify_chain(rows)
        self.assertEqual((r.first_bad_seq, r.kind), (11, "reordered"))

    def test_truncated_tail_needs_head(self):
        head = (self.rows[-1]["seq"], self.rows[-1]["hash"])
        tail_cut = copy.deepcopy(self.rows)[:-3]
        self.assertTrue(verify_chain(tail_cut).ok)  # not detectable alone
        r = verify_chain(tail_cut, expected_head=head)
        self.assertEqual((r.first_bad_seq, r.kind), (998, "deleted"))

    def test_mixed_tenants_rejected(self):
        rows = _chain(2) + _chain(2, "t2")
        self.assertFalse(verify_chain(rows).ok)

    def test_failure_is_reportable_as_event(self):
        rows = copy.deepcopy(self.rows); rows[5]["actor"] = "evil"
        ev = verify_chain(rows).as_event()
        self.assertEqual(ev["event_type"], "audit.verify.failed")
        self.assertEqual(ev["subject_id"], "6")


POLICY_A = {"hash": "a" * 64, "evaluate": lambda inp: {"allow": inp["tool"] == "ok", "reasons": []}}


class Replay(unittest.TestCase):
    def _rec(self, inp, bundle, result):
        return {"policy_hash": bundle["hash"], "input": inp,
                "input_digest": input_digest(inp), "decision": "allow" if result else "deny"}

    def test_replay_matches(self):
        recs = [self._rec({"tool": t}, POLICY_A, t == "ok") for t in ("ok", "bad", "ok")]
        rep = replay_decisions(recs, {POLICY_A["hash"]: POLICY_A["evaluate"]})
        self.assertEqual((rep.checked, rep.mismatches), (3, []))

    def test_mismatch_reported(self):
        recs = [self._rec({"tool": "ok"}, POLICY_A, False)]
        rep = replay_decisions(recs, {POLICY_A["hash"]: POLICY_A["evaluate"]})
        self.assertEqual(len(rep.mismatches), 1)

    def test_missing_bundle_is_a_failure_not_a_skip(self):
        recs = [self._rec({"tool": "ok"}, POLICY_A, True)]
        rep = replay_decisions(recs, {})
        self.assertEqual(len(rep.mismatches), 1)
        self.assertIn("bundle", rep.mismatches[0]["reason"])

    def test_input_digest_mismatch_detected(self):
        r = self._rec({"tool": "ok"}, POLICY_A, True)
        r["input"] = {"tool": "other"}
        rep = replay_decisions([r], {POLICY_A["hash"]: POLICY_A["evaluate"]})
        self.assertIn("digest", rep.mismatches[0]["reason"])

    def test_evaluator_exception_is_mismatch(self):
        def boom(_): raise RuntimeError("x")
        r = self._rec({"tool": "ok"}, POLICY_A, True)
        rep = replay_decisions([r], {POLICY_A["hash"]: boom})
        self.assertEqual(len(rep.mismatches), 1)

    def test_digest_is_key_order_independent(self):
        self.assertEqual(input_digest({"a": 1, "b": 2}), input_digest({"b": 2, "a": 1}))


class Vocabulary(unittest.TestCase):
    def test_equals_architecture_section_4_8(self):
        import pathlib

        from agenticsecctl_common.contracts import EVENT_TYPES
        text = (pathlib.Path(__file__).resolve().parents[3] / "Plan/architecture.md").read_text()
        block = text.split("Audit event vocabulary", 1)[1].split("Names are confirmed", 1)[0]
        doc = set(__import__("re").findall(r"`([a-z_]+\.[a-z_.]+)`", block))
        self.assertEqual(doc, set(EVENT_TYPES))


if __name__ == "__main__":
    unittest.main()
