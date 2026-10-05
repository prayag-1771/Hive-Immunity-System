"""The simulated Bluetooth bulb speaks exactly the report format the ESP32 hub accepts."""

import os
import random
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import ble_bulb  # noqa: E402  (bleak is only imported when the bulb actually runs)

# Mirror of bleValidReport() in firmware/hive_node/ble_hub.h
REPORT = re.compile(rb"^[a-z0-9]{1,10}:[0-9]{1,6}:[01]$")


class BleBulbFormat(unittest.TestCase):
    def test_reports_are_valid_and_fit_the_default_mtu(self):
        for seq in (1, 42, 999_999, 1_000_001, 12_345_678):
            for light in (False, True):
                r = ble_bulb.report("blebulb", seq, light)
                self.assertRegex(r, REPORT)
                self.assertLessEqual(len(r), 20)

    def test_flood_is_never_a_valid_report(self):
        rng = random.Random(3)
        for i in range(5000):
            j = ble_bulb.junk(rng, i)
            self.assertIsNone(REPORT.match(j))
            self.assertLessEqual(len(j), 20)

    def test_uuids_match_the_firmware(self):
        header = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   "firmware", "hive_node", "ble_hub.h"), encoding="utf-8").read()
        self.assertIn(f'#define BLE_SERVICE_UUID "{ble_bulb.SERVICE}"', header)
        self.assertIn(f'#define BLE_REPORT_UUID "{ble_bulb.REPORT}"', header)


class BleBulbRecovery(unittest.TestCase):
    def test_failed_connect_makes_bluez_let_go(self):
        bulb = ble_bulb.Bulb.__new__(ble_bulb.Bulb)   # no __init__: it opens a UDP socket
        calls = []
        with mock.patch.object(ble_bulb.subprocess, "run", side_effect=lambda cmd, **kw: calls.append(cmd)), \
                mock.patch.object(bulb, "log", create=True):
            bulb.release("68:FE:71:80:0A:E2")
            bulb.release("68:FE:71:80:0A:E2", forget=True)
        self.assertEqual(calls, [["bluetoothctl", "disconnect", "68:FE:71:80:0A:E2"],
                                 ["bluetoothctl", "disconnect", "68:FE:71:80:0A:E2"],
                                 ["bluetoothctl", "remove", "68:FE:71:80:0A:E2"]])


if __name__ == "__main__":
    unittest.main()
