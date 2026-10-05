"""tools/demo_wifi.py reads netsh output correctly (the netsh calls themselves are Windows-only)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import demo_wifi  # noqa: E402

PROFILES = """
Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : Moto Edge 50 Pro
    All User Profile     : VITC-EVENT
    All User Profile     : R Sudarsan
"""

PROFILE = """
Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "VITC-EVENT"
    Network type           : Infrastructure
    Radio type             : [ Any Radio Type ]
    Vendor extension          : Not present

    Connection mode        : Connect automatically
"""


class DemoWifi(unittest.TestCase):
    def test_profile_names(self):
        self.assertEqual(demo_wifi.parse_profiles(PROFILES), ["Moto Edge 50 Pro", "VITC-EVENT", "R Sudarsan"])

    def test_connection_mode(self):
        self.assertTrue(demo_wifi.parse_auto(PROFILE))
        self.assertFalse(demo_wifi.parse_auto(PROFILE.replace("automatically", "manually")))
        self.assertIsNone(demo_wifi.parse_auto("Profile X is not found on the system."))


if __name__ == "__main__":
    unittest.main()
