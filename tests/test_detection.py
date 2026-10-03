"""Learning, detection, quarantine, blocking, healing and signed control messages."""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))
import hive_core as hc  # noqa: E402

KEYS = {"lapA": "01" * 32, "lapB": "02" * 32}
ADMIN = "aa" * 32
HUB = "10.0.0.1"
ME = "10.0.0.3"
ATTACKER = "10.0.0.66"
DEMO = {"learn_seconds": 10, "quarantine_hold_s": 5}


def cmd(seq, c="ping"):
    return hc.encode({"v": 1, "t": "cmd", "src": "hub", "dst": "lapA", "cmd": c, "seq": seq})


class Sim:
    """Drives a node with hub traffic (~3 msg/s with jitter) at 0.05 s resolution."""

    def __init__(self, **demo):
        self.rng = random.Random(7)
        self.node = hc.HiveNode("lapA", KEYS["lapA"], KEYS, ADMIN, {**DEMO, **demo}, 2, my_ip=ME)
        self.t = 0.0
        self.seq = 0

    def run(self, seconds, attack_rate=0):
        end = self.t + seconds
        while self.t < end:
            if self.rng.random() < 3 * 0.05:
                self.seq += 1
                self.node.on_data(HUB, cmd(self.seq), self.t)
            for _ in range(int(attack_rate * 0.05)):
                self.node.on_data(ATTACKER, bytes(self.rng.randrange(256) for _ in range(40)), self.t)
            self.t = round(self.t + 0.05, 2)
            self.node.tick(self.t)

    def kinds(self):
        events, vax = self.node.drain()
        return [e["kind"] for e in events], vax


class Detection(unittest.TestCase):
    def learned(self, **demo):
        s = Sim(**demo)
        s.run(12)
        self.assertEqual(s.node.state, "healthy")
        self.assertEqual(s.node.hub_ip, HUB)
        self.assertIn(HUB, s.node.baseline.known)
        s.kinds()
        return s

    def test_waits_for_hub_before_learning(self):
        s = Sim()
        s.node.tick(5)
        self.assertEqual((s.node.state, s.node.learn_start), ("learning", None))

    def test_normal_traffic_stays_healthy(self):
        s = self.learned()
        s.run(60)
        self.assertEqual(s.node.state, "healthy")
        self.assertLess(s.node.score, s.node.detector.threshold)

    def test_no_false_alarms_over_ten_minutes(self):
        for seed in range(5):
            s = Sim()
            s.rng.seed(seed)
            s.run(12)
            s.run(600)
            kinds, _ = s.kinds()
            self.assertNotIn("quarantine", kinds, f"seed {seed}")

    def test_empty_window_is_not_an_anomaly(self):
        s = self.learned()
        s.node.window = hc.Window()
        s.node.window_start = s.t
        s.node.tick(s.t + 1.0)
        self.assertLess(s.node.score, s.node.detector.threshold)

    def test_attack_quarantines_blocks_and_vaccinates(self):
        s = self.learned()
        s.run(3, attack_rate=50)
        kinds, vax = s.kinds()
        self.assertEqual(s.node.state, "quarantined")
        self.assertIn("quarantine", kinds)
        self.assertIn("vax_issued", kinds)
        self.assertTrue(s.node.is_blocked(ATTACKER, s.t))
        self.assertEqual(len(vax), 1)
        v = vax[0]
        self.assertEqual((v["issuer"], v["target"], v["rule"]), ("lapA", ATTACKER, "block"))
        self.assertEqual(v["reason"], "malformed")
        self.assertTrue(hc.valid_vax(v) and hc.verify(KEYS["lapA"], v))
        self.assertTrue(s.node.dirty)

    def test_detects_within_about_two_windows(self):
        s = self.learned()
        start = s.t
        while s.node.state != "quarantined" and s.t - start < 5:
            s.run(0.05, attack_rate=50)
        self.assertLessEqual(s.t - start, 2.2)

    def test_blocked_attacker_is_logged_once_then_heals(self):
        s = self.learned()
        s.run(3, attack_rate=50)
        first, _ = s.kinds()
        before = s.node.blocked
        s.run(1, attack_rate=50)
        kinds, _ = s.kinds()
        self.assertGreater(s.node.blocked, before)
        self.assertEqual((first + kinds).count("blocked_first_packet"), 1)
        s.run(8)
        kinds, _ = s.kinds()
        self.assertIn("heal", kinds)
        self.assertEqual(s.node.state, "healthy")

    def test_preimmunised_node_never_quarantines(self):
        s = self.learned()
        s.node._block(ATTACKER, 300, s.t)
        s.run(3, attack_rate=50)
        kinds, vax = s.kinds()
        self.assertEqual(s.node.state, "healthy")
        self.assertEqual(kinds, ["blocked_first_packet"])
        self.assertEqual(vax, [])

    def test_signed_reset_and_rejected_forgery(self):
        s = self.learned()
        s.run(3, attack_rate=50)
        s.kinds()
        s.node.on_data(ATTACKER, hc.encode(hc.make_ctrl("bb" * 32, "reset", 1)), s.t)
        self.assertEqual(s.node.state, "quarantined")
        s.node.on_data(HUB, hc.encode(hc.make_ctrl(ADMIN, "reset", 2)), s.t)
        self.assertEqual(s.node.state, "healthy")
        self.assertEqual(s.node.blocklist, {})
        # Replaying the same signed reset does nothing.
        s.node.on_data(HUB, hc.encode(hc.make_ctrl(ADMIN, "reset", 2)), s.t)
        self.assertEqual(s.kinds()[0], ["heal", "ctrl_rejected"])

    def test_relearn(self):
        s = self.learned()
        s.node.on_data(HUB, hc.encode(hc.make_ctrl(ADMIN, "relearn", 1)), s.t)
        self.assertEqual(s.node.state, "learning")
        s.run(12)
        self.assertEqual(s.node.state, "healthy")

    def test_baseline_roundtrip(self):
        s = self.learned()
        b = hc.Baseline.from_dict(s.node.baseline.to_dict())
        self.assertEqual(b.mean, s.node.baseline.mean)
        self.assertEqual(b.known, s.node.baseline.known)

    def test_status_fits_in_one_datagram(self):
        s = self.learned()
        for i in range(8):
            s.node._block(f"198.18.0.{i}", 300, s.t)
            s.node.pending[f"198.19.0.{i}"] = {"rogue": s.t}
        self.assertLess(len(hc.encode(s.node.status(s.t, 1.7e9))), 1024)


if __name__ == "__main__":
    unittest.main()
