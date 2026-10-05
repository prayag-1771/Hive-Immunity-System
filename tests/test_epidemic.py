"""SIR epidemic projection: R0<1 dies out, R0>1 spreads, and faster Hive always lowers R0."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dashboard"))
sys.path.insert(0, os.path.join(ROOT, "agent"))
import epidemic  # noqa: E402
import hive_core as hc  # noqa: E402


class SIR(unittest.TestCase):
    def test_outbreak_dies_out_when_R0_below_1(self):
        # gamma well above beta -> R0 < 1 -> almost nobody beyond the seed is infected.
        out = epidemic.simulate(n=10000, beta=0.4, gamma=2.0, i0=1, steps=400)
        self.assertLess(out["R0"], 1.0)
        self.assertLess(out["final_infected"], 100)      # contained
        self.assertLessEqual(out["peak_infected"], 20)

    def test_outbreak_spreads_when_R0_above_1(self):
        out = epidemic.simulate(n=10000, beta=3.0, gamma=0.3, i0=1, steps=600)
        self.assertGreater(out["R0"], 1.0)
        self.assertGreater(out["final_infected"], 9000)  # most of the city

    def test_without_immunity_infects_almost_everyone(self):
        out = epidemic.simulate(n=10000, beta=2.0, gamma=0.0, i0=1, steps=800)
        self.assertIsNone(out["R0"])   # no recovery -> undefined R0, serialized as JSON null
        self.assertGreater(out["final_infected"], 9900)

    def test_result_is_valid_json_no_infinity(self):
        import json
        out = epidemic.project({"t_detect": 1.6, "t_spread": 0.2}, hc.EPIDEMIC_DEFAULTS)
        reparsed = json.loads(json.dumps(out, allow_nan=False))   # raises if any inf/nan leaks
        self.assertIsNone(reparsed["without_hive"]["R0"])

    def test_counts_are_conserved_and_non_negative(self):
        out = epidemic.simulate(n=1000, beta=1.5, gamma=0.4, i0=5, steps=300)
        for s, i, r in zip(out["S"], out["I"], out["R"]):
            self.assertGreaterEqual(min(s, i, r), -1e-9)
            self.assertAlmostEqual(s + i + r, 1000, places=3)

    def test_faster_hive_lowers_R0_monotonically(self):
        r0s = []
        for t in (0.5, 1.0, 2.0, 4.0, 8.0):   # slower detection+spread
            beta, gamma = epidemic.derive_params(t, 0.0, attacker_fanout_per_s=5, contact_factor=0.6)
            r0s.append(beta / gamma)
        self.assertEqual(r0s, sorted(r0s))    # slower Hive -> higher R0, strictly ordered
        self.assertTrue(all(a < b for a, b in zip(r0s, r0s[1:])))


class Project(unittest.TestCase):
    CFG = hc.EPIDEMIC_DEFAULTS   # test the numbers we actually ship

    def test_measured_demo_speed_contains_the_outbreak(self):
        out = epidemic.project({"t_detect": 1.6, "t_spread": 0.2}, self.CFG)
        self.assertTrue(out["contained"])
        self.assertLess(out["with_hive"]["R0"], 1.0)
        self.assertGreater(out["without_hive"]["final_infected"], out["with_hive"]["final_infected"])
        self.assertGreater(out["saved_pct"], 50.0)

    def test_a_much_slower_response_would_not_contain_it(self):
        # the honest flip side: if detection + spread were far slower, R0 climbs above 1.
        out = epidemic.project({"t_detect": 6.0, "t_spread": 6.0}, self.CFG)
        self.assertFalse(out["contained"])
        self.assertGreaterEqual(out["with_hive"]["R0"], 1.0)

    def test_city_size_is_respected(self):
        out = epidemic.project({"t_detect": 1.0, "t_spread": 1.0}, {**self.CFG, "city_size": 500})
        self.assertEqual(out["city_size"], 500)
        self.assertEqual(out["with_hive"]["n"], 500)


if __name__ == "__main__":
    unittest.main()
