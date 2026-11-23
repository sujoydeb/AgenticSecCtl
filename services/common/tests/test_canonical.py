"""WP-1.2 tests: RFC 8785 canonical JSON and the tool-definition hash."""
import math
import unittest

from agenticsecctl_common.canonical import canonicalize, sha256_hex
from agenticsecctl_common.tooldef import HASHED_FIELDS, tool_definition_hash

BASE = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}


class Rfc8785(unittest.TestCase):
    def test_key_order_utf16(self):
        # RFC 8785 section 3.2.3: sort by UTF-16 code units
        obj = {"€": "Euro", "\r": "CR", "דּ": "Hebrew", "1": "one",
               "\U0001f600": "emoji", "\u0080": "ctl", "ö": "o-umlaut"}
        out = canonicalize(obj).decode()
        order = sorted(obj, key=lambda k: k.encode("utf-16-be"))
        self.assertEqual(order[0], "\r")
        self.assertLess(out.index('"\U0001f600"'), out.index('"דּ"'))

    def test_rfc_number_vectors(self):
        vec = {
            0.0: "0", 1.0: "1", 1e21: "1e+21", 1e-7: "1e-7",
            123456789012345680000.0: "123456789012345680000",
            4.5: "4.5", 0.002: "0.002", 1e30: "1e+30",
            9007199254740991.0: "9007199254740991",
            5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308",
            333333333.33333329: "333333333.3333333",
            0.000001: "0.000001",
        }
        for value, text in vec.items():
            self.assertEqual(canonicalize(value).decode(), text, value)

    def test_negative_zero(self):
        self.assertEqual(canonicalize(-0.0).decode(), "0")

    def test_rejects_nan_inf(self):
        for bad in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                canonicalize(bad)

    def test_rfc_example(self):
        obj = {"numbers": [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
               "string": "\u20ac$\x0f\nA'B" + '"' + "\\\\" + '"/',
               "literals": [None, True, False]}
        expect = ('{"literals":[null,true,false],"numbers":[333333333.3333333,'
                  '1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
        self.assertEqual(canonicalize(obj).decode(), expect)

    def test_ints_and_bool_not_confused(self):
        self.assertEqual(canonicalize([1, True, 0, False]).decode(), "[1,true,0,false]")
        with self.assertRaises(ValueError):
            canonicalize(2**53)  # beyond the I-JSON safe range

    def test_non_string_key_rejected(self):
        with self.assertRaises(TypeError):
            canonicalize({1: "x"})

    def test_stable_hash(self):
        self.assertEqual(sha256_hex(canonicalize({"b": 1, "a": 2})),
                         sha256_hex(canonicalize({"a": 2, "b": 1})))


class ToolDefHash(unittest.TestCase):
    def h(self, tool, server="s1"):
        return tool_definition_hash(server, tool).digest

    def test_each_field_changes_hash(self):
        full = {"name": "t", "title": "T", "description": "d", "icons": [{"src": "a"}],
                "inputSchema": {"type": "object"}, "outputSchema": {"type": "object"},
                "annotations": {"readOnlyHint": True}}
        self.assertEqual(set(full), set(HASHED_FIELDS))
        base = self.h(full)
        for field in HASHED_FIELDS:
            changed = dict(full)
            changed[field] = {"x": 1} if field != "name" else "u"
            self.assertNotEqual(self.h(changed), base, field)

    def test_server_id_in_hash(self):
        self.assertNotEqual(self.h(BASE, "s1"), self.h(BASE, "s2"))

    def test_unhashed_metadata(self):
        base = self.h(BASE)
        for extra in ({"_meta": {"a": 1}}, {"ttlMs": 5}, {"cacheScope": "x"}, {"resultType": "r"}):
            r = tool_definition_hash("s1", {**BASE, **extra})
            self.assertEqual(r.digest, base, extra)
            self.assertEqual(r.unknown_fields, ())

    def test_unknown_field_hashed_and_reported(self):
        r = tool_definition_hash("s1", {**BASE, "x-extra": 1})
        self.assertNotEqual(r.digest, self.h(BASE))
        self.assertEqual(r.unknown_fields, ("x-extra",))

    def test_absent_vs_null(self):
        self.assertNotEqual(self.h({**BASE, "title": None}), self.h(BASE))

    def test_array_order_significant(self):
        a = {**BASE, "icons": [{"src": "a"}, {"src": "b"}]}
        b = {**BASE, "icons": [{"src": "b"}, {"src": "a"}]}
        self.assertNotEqual(self.h(a), self.h(b))

    def test_nfc_applied(self):
        a = {**BASE, "description": "café"}
        b = {**BASE, "description": "café"}
        self.assertEqual(self.h(a), self.h(b))

    def test_key_order_irrelevant(self):
        self.assertEqual(self.h({"description": "d", "name": "t", "inputSchema": {"type": "object"}}),
                         self.h(BASE))


if __name__ == "__main__":
    unittest.main()
