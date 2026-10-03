"""Dashboard bookkeeping: time to immunity, 'blocked instantly', the defence checklist."""

import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
import hive_core as hc  # noqa: E402
import server  # noqa: E402

ATT = "10.0.0.66"


def config():
    cfg = {
        "network": {**hc.NETWORK_DEFAULTS, "status_port": 0, "broadcast": None},
        "demo": dict(hc.DEMO_DEFAULTS), "quorum": 2,
        "hub": {"node_id": "hub", "ip": "127.0.0.1"}, "dashboard": {"ip": "127.0.0.1"},
        "attacker": {"ip": "auto"}, "dumb": {"name": "bulb", "ip": "auto"},
        "nodes": [{"node_id": n, "kind": "python", "key": "00" * 32, "ip": "auto"} for n in ("esp32", "lapA", "lapB")],
        "issuers": [{"node_id": "gateway", "kind": "gateway", "key": "11" * 32, "ip": "auto"}],
        "admin_key": "aa" * 32, "protected": [], "_path": "test.json",
    }
    return cfg


class DashboardState(unittest.TestCase):
    def setUp(self):
        self.d = server.Dashboard(config(), run_hub=False)
        for i, n in enumerate(("esp32", "lapA", "lapB")):
            self.status(n, f"127.0.9.{i + 2}")

    def tearDown(self):
        self.d.sock.close()

    def status(self, node, ip, blocklist=(), at=None):
        self.d.clock = (lambda: at) if at is not None else time.time
        self.d._on_msg({"v": 1, "t": "status", "node": node, "state": "healthy", "blocklist": list(blocklist)}, ip)

    def event(self, node, kind, detail="", target=None, ts=None):
        """ts = when the dashboard receives it (its own clock); the sender's ts is ignored."""
        self.d.clock = (lambda: ts) if ts is not None else time.time
        msg = {"v": 1, "t": "event", "node": node, "kind": kind, "detail": detail, "ts": 12345.0}
        if target:
            msg["target"] = target
        self.d._on_msg(msg, "127.0.9.99")

    def test_time_to_immunity(self):
        self.event("attacker", "attack_started", "flooding", ATT, ts=100.0)
        self.event("esp32", "vax_issued", "block", ATT, ts=102.0)
        self.event("lapA", "vax_pending", "pending 1/2", ATT, ts=102.1)
        snap = self.d.snapshot()["immunity"]
        self.assertEqual((snap["t0"], snap["t1"]), (100.0, None))
        self.event("lapB", "vax_issued", "block", ATT, ts=108.0)
        self.event("lapA", "vax_adopted", "immune", ATT, ts=108.2)
        snap = self.d.snapshot()["immunity"]
        self.assertAlmostEqual(snap["t1"] - snap["t0"], 8.2)
        self.assertEqual(snap["nodes"], {"esp32": "detected", "lapB": "detected", "lapA": "adopted"})

    def test_blocked_instantly_only_after_adoption(self):
        self.event("attacker", "attack_started", "", ATT, ts=1.0)
        self.event("esp32", "vax_issued", "", ATT, ts=2.0)
        self.event("esp32", "blocked_first_packet", "", ATT, ts=2.1)
        self.event("lapA", "vax_adopted", "", ATT, ts=3.0)
        self.event("lapA", "blocked_first_packet", "", ATT, ts=4.0)
        self.assertEqual(self.d.snapshot()["immunity"]["instant"], {"lapA": 4.0})

    def test_duplicate_event_copies_are_dropped(self):
        self.event("gateway", "quarantine", "bulb isolated", "10.0.0.20", ts=10.0)
        self.event("gateway", "quarantine", "bulb isolated", "10.0.0.20", ts=10.05)
        self.event("gateway", "quarantine", "bulb isolated", "10.0.0.20", ts=20.0)
        self.assertEqual(sum(e["kind"] == "quarantine" for e in self.d.events), 2)

    def test_sender_clock_is_ignored(self):
        self.event("attacker", "attack_started", "", ATT, ts=500.0)
        self.assertEqual(self.d.snapshot()["immunity"]["t0"], 500.0)

    def test_status_blocklist_counts_as_immune(self):
        self.event("attacker", "attack_started", "", ATT, ts=1.0)
        for i, n in enumerate(("esp32", "lapA", "lapB")):
            self.status(n, f"127.0.9.{i + 2}", blocklist=[ATT])
        self.assertIsNotNone(self.d.snapshot()["immunity"]["t1"])

    def test_offline_node_does_not_block_completion(self):
        self.d.nodes["lapB"]["seen"] = 0.0
        self.event("attacker", "attack_started", "", ATT, ts=1.0)
        self.event("esp32", "vax_issued", "", ATT, ts=2.0)
        self.event("lapA", "vax_adopted", "", ATT, ts=3.0)
        self.assertEqual(self.d.snapshot()["immunity"]["t1"], 3.0)

    def test_defence_checklist(self):
        for reason in ("forged", "garbage", "replay", "protected_target", "autoimmune"):
            self.event("lapA", "vax_rejected", f"{reason}: detail")
        self.event("lapA", "vax_pending", "10.0.0.4 pending 1/2 (from rogue)", "10.0.0.4")
        self.assertEqual(set(self.d.snapshot()["defenses"]),
                         {"forged", "garbage", "replay", "protected_target", "autoimmune", "quorum"})

    def test_reset_clears_timer_and_checklist(self):
        self.event("attacker", "attack_started", "", ATT, ts=1.0)
        self.event("lapA", "vax_rejected", "forged: x")
        self.d.reset()
        snap = self.d.snapshot()
        self.assertIsNone(snap["immunity"]["t0"])
        self.assertEqual(snap["defenses"], {})

    def test_template_explanation_grammar(self):
        self.event("attacker", "attack_started", "", ATT, ts=1.0)
        self.event("esp32", "quarantine", "score", ATT)
        self.event("lapB", "quarantine", "score", ATT)
        self.event("lapA", "vax_adopted", "immune", ATT)
        text = self.d._template(list(self.d.events), {})
        self.assertIn("ESP32 and Laptop B each noticed", text)
        self.assertIn("isolated themselves", text)
        self.assertIn("before it ever reached it", text)


if __name__ == "__main__":
    unittest.main()
