"""Fixed key + fixed vaccine -> expected signature.

The same vector is checked by the firmware's host test (firmware/hive_node/test/), so the
Python agents and the ESP32 provably build the same bytes and the same HMAC. The expected
hex was produced independently with `openssl dgst -sha256 -mac HMAC`.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))
import hive_core  # noqa: E402

KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
VAX = {"v": 1, "t": "vax", "issuer": "esp32", "seq": 7, "rule": "block",
       "target": "10.42.0.66", "ttl": 300, "reason": "flood"}
CANONICAL = (b'{"issuer":"esp32","reason":"flood","rule":"block","seq":7,'
             b'"t":"vax","target":"10.42.0.66","ttl":300,"v":1}')
EXPECTED = "f55b1d5eafed736fb46a49608ae74ffc905b430902a3c73d3b3df59c226b1700"


class HmacVector(unittest.TestCase):
    def test_canonical_bytes(self):
        self.assertEqual(hive_core.canonical(VAX), CANONICAL)

    def test_canonical_ignores_sig_and_key_order(self):
        shuffled = dict(reversed(list(VAX.items())))
        shuffled["sig"] = "ff" * 32
        self.assertEqual(hive_core.canonical(shuffled), CANONICAL)

    def test_signature(self):
        self.assertEqual(hive_core.sign(KEY, VAX), EXPECTED)

    def test_make_vax_matches_vector(self):
        m = hive_core.make_vax("esp32", KEY, 7, "10.42.0.66", 300, "flood")
        self.assertEqual(m["sig"], EXPECTED)
        self.assertTrue(hive_core.valid_vax(m))
        self.assertTrue(hive_core.verify(KEY, m))

    def test_tampered_target_fails(self):
        m = hive_core.make_vax("esp32", KEY, 7, "10.42.0.66", 300, "flood")
        m["target"] = "10.42.0.67"
        self.assertFalse(hive_core.verify(KEY, m))


if __name__ == "__main__":
    unittest.main()
