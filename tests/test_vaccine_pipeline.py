"""Every way a vaccine can be refused, plus quorum adoption."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))
import hive_core as hc  # noqa: E402

KEYS = {name: f"{i:02x}" * 32 for i, name in enumerate(["lapA", "lapB", "esp32", "rogue", "gateway"], 1)}
ADMIN = "aa" * 32
HUB = "10.0.0.1"
ME = "10.0.0.3"
ATTACKER = "10.0.0.66"


def node(quorum=2, **demo):
    return hc.HiveNode("lapA", KEYS["lapA"], KEYS, ADMIN, demo, quorum,
                       my_ip=ME, hub_ip=HUB, baseline=hc.Baseline())


def vax(issuer, seq, target=ATTACKER, ttl=300, reason="flood", key=None):
    return hc.encode(hc.make_vax(issuer, key or KEYS[issuer], seq, target, ttl, reason))


def kinds(n):
    events, _ = n.drain()
    return [(e["kind"], e["detail"].split(":")[0]) for e in events]


class VaccinePipeline(unittest.TestCase):
    def test_quorum_of_two_adopts(self):
        n = node()
        n.on_vax("10.0.0.2", vax("esp32", 1), 0)
        self.assertFalse(n.is_blocked(ATTACKER, 1))
        self.assertEqual(n.status(1, 0)["pending"], [[ATTACKER, 1]])
        n.on_vax("10.0.0.4", vax("lapB", 1), 2)
        self.assertTrue(n.is_blocked(ATTACKER, 3))
        self.assertEqual(n.vax_adopted, 1)
        self.assertEqual(n.pending, {})
        self.assertIn(("vax_adopted", "immune to 10.0.0.66 (reports from esp32, lapB)"), kinds(n))

    def test_same_issuer_twice_is_not_quorum(self):
        n = node()
        n.on_vax("10.0.0.2", vax("esp32", 1), 0)
        n.on_vax("10.0.0.2", vax("esp32", 2), 1)
        self.assertFalse(n.is_blocked(ATTACKER, 2))

    def test_quorum_one(self):
        n = node(quorum=1)
        n.on_vax("10.0.0.2", vax("esp32", 1), 0)
        self.assertTrue(n.is_blocked(ATTACKER, 1))

    def test_forged_signature(self):
        n = node()
        n.on_vax("10.0.0.66", vax("esp32", 5, key="ee" * 32), 0)
        self.assertEqual(n.vax_rejected, 1)
        self.assertEqual(kinds(n), [("vax_rejected", "forged")])
        # A forgery must not advance the replay counter of the real issuer.
        n.on_vax("10.0.0.2", vax("esp32", 1), 1)
        self.assertEqual(n.vax_rejected, 1)

    def test_tampered_vaccine(self):
        n = node()
        m = hc.make_vax("esp32", KEYS["esp32"], 1, ATTACKER, 300, "flood")
        m["target"] = "10.0.0.4"
        n.on_vax("10.0.0.66", hc.encode(m), 0)
        self.assertEqual(kinds(n), [("vax_rejected", "forged")])

    def test_replay_of_older_seq(self):
        n = node()
        n.on_vax("10.0.0.2", vax("esp32", 5), 0)
        n.on_vax("10.0.0.2", vax("esp32", 4), 1)
        self.assertIn(("vax_rejected", "replay"), kinds(n))

    def test_identical_duplicate_is_silent(self):
        n = node()
        raw = vax("esp32", 5)
        n.on_vax("10.0.0.2", raw, 0)
        n.on_vax("10.0.0.2", raw, 0.01)   # same packet via broadcast and unicast
        self.assertEqual(n.vax_rejected, 0)

    def test_oversized(self):
        n = node()
        n.on_vax("10.0.0.66", b"{" + b" " * 400 + b"}", 0)
        self.assertEqual(kinds(n), [("vax_rejected", "garbage")])

    def test_garbage_and_schema(self):
        n = node()
        bad = [
            b"\xff\xfe not json",
            b"[1,2,3]",
            json.dumps({"v": 1, "t": "vax"}).encode(),
        ]
        m = hc.make_vax("esp32", KEYS["esp32"], 1, ATTACKER, 300, "flood")
        for field, value in [("rule", "allow"), ("ttl", 601), ("ttl", True), ("target", "1.2.3"),
                             ("reason", "because"), ("issuer", "a b"), ("seq", -1)]:
            bad.append(hc.encode({**m, field: value}))
        bad.append(hc.encode({**m, "extra": 1}))
        for i, raw in enumerate(bad):
            n.on_vax("10.0.0.66", raw, i)
        self.assertEqual(n.vax_rejected, len(bad))
        self.assertTrue(all(k == ("vax_rejected", "garbage") for k in kinds(n)))

    def test_unknown_issuer(self):
        n = node()
        n.on_vax("10.0.0.66", vax("lapZ", 1, key="11" * 32), 0)
        self.assertEqual(kinds(n), [("vax_rejected", "unknown_issuer")])

    def test_own_vaccine_echo_is_ignored(self):
        n = node()
        n.on_vax(ME, vax("lapA", 1), 0)
        self.assertEqual((n.vax_rejected, n.pending), (0, {}))

    def test_protected_targets(self):
        n = node(quorum=1)
        n.on_vax("10.0.0.2", vax("esp32", 1, target=HUB), 0)
        n.on_vax("10.0.0.2", vax("esp32", 2, target=ME), 1)
        self.assertEqual(kinds(n), [("vax_rejected", "protected_target")] * 2)
        self.assertEqual(n.blocklist, {})

    def test_autoimmune_flood_distrusts_and_drops_votes(self):
        n = node(vax_rate_max_per_min=3, distrust_s=300)
        for seq in range(1, 7):
            n.on_vax("10.0.0.66", vax("rogue", seq, target=f"198.18.0.{seq}"), seq * 0.1)
        got = [k for k in kinds(n)]
        self.assertEqual(got[:3], [("vax_pending", "198.18.0.1 pending 1/2 (from rogue)"),
                                   ("vax_pending", "198.18.0.2 pending 1/2 (from rogue)"),
                                   ("vax_pending", "198.18.0.3 pending 1/2 (from rogue)")])
        self.assertEqual(got[3], ("vax_rejected", "autoimmune"))
        self.assertEqual(got[4:], [("vax_rejected", "distrusted")] * 2)
        self.assertTrue(all(not votes for votes in n.pending.values()))
        # Distrust wears off.
        n.on_vax("10.0.0.66", vax("rogue", 50), 400)
        self.assertEqual(kinds(n)[-1][0], "vax_pending")

    def test_single_report_against_legit_device_never_adopts(self):
        n = node()
        n.on_vax("10.0.0.66", vax("rogue", 1, target="10.0.0.4"), 0)
        n.tick(1)
        self.assertFalse(n.is_blocked("10.0.0.4", 1))
        # Pending votes age out.
        n.tick(500)
        self.assertEqual(n.pending, {})

    def test_vaccine_can_only_block_and_expires(self):
        n = node(quorum=1)
        n.on_vax("10.0.0.2", vax("esp32", 1, ttl=10), 0)
        self.assertTrue(n.is_blocked(ATTACKER, 5))
        n.tick(11)
        self.assertFalse(n.is_blocked(ATTACKER, 11))
        self.assertNotIn(ATTACKER, n.blocklist)


if __name__ == "__main__":
    unittest.main()
