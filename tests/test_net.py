"""UDP helpers: oversized datagrams must arrive whole, never crash the receive loop."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402


class RecvAll(unittest.TestCase):
    def test_oversized_datagram_then_normal_traffic(self):
        rx = net.udp_socket("127.0.0.1", 0)
        tx = net.udp_socket("127.0.0.1", 0)
        addr = rx.getsockname()
        try:
            tx.sendto(b"A" * 3000, addr)
            tx.sendto(b'{"v":1,"t":"cmd"}', addr)
            got = []
            end = time.time() + 2
            while len(got) < 2 and time.time() < end:
                got += list(net.recv_all(rx))
                time.sleep(0.01)
            self.assertEqual([len(d) for d, _ in got], [3000, 17])
            self.assertIsNone(hc.parse(got[0][0]))  # rejected by the size check, not truncated
        finally:
            rx.close()
            tx.close()


class LocalSegmentGuard(unittest.TestCase):
    """Hive never sends outside the machine's own network (brief's safety rule)."""

    def test_loopback_and_limited_broadcast_allowed(self):
        self.assertTrue(net.on_local_segment("127.0.0.5"))
        self.assertTrue(net.on_local_segment("255.255.255.255"))

    def test_internet_address_refused(self):
        self.assertFalse(net.on_local_segment("8.8.8.8"))
        self.assertFalse(net.on_local_segment("1.1.1.1"))

    def test_own_segment_allowed(self):
        mine = net.guess_lan_ip()
        if mine.startswith("127."):
            self.skipTest("no LAN interface on this machine")
        self.assertTrue(net.on_local_segment(mine.rsplit(".", 1)[0] + ".250"))

    def test_send_to_internet_is_dropped_quietly(self):
        s = net.udp_socket("0.0.0.0", 0)
        try:
            net.send(s, b"x", ("8.8.8.8", 47000))  # must neither raise nor send
        finally:
            s.close()

    def test_limited_broadcast_only_on_the_demo_network(self):
        cfg = {"esp32": {"ssid": "HiveNet"}, "dashboard": {"ip": "auto"}, "nodes": []}
        try:
            net.set_demo_network(cfg)
            with mock.patch.object(net, "wifi_ssids", return_value=["Campus WiFi"]):
                self.assertFalse(net.on_local_segment("255.255.255.255"))
                mine = net.guess_lan_ip()
                if not mine.startswith("127."):   # not even that network's own addresses
                    self.assertFalse(net.on_local_segment(mine.rsplit(".", 1)[0] + ".255"))
                self.assertTrue(net.on_local_segment("127.0.0.5"))   # this machine itself: always
            net.set_demo_network(cfg)   # forget the cached answer
            with mock.patch.object(net, "wifi_ssids", return_value=["HiveNet"]):
                self.assertTrue(net.on_local_segment("255.255.255.255"))
            net.set_demo_network({"dashboard": {"ip": "127.0.0.1"}, "nodes": [{"ip": "127.0.0.2"}]})
            self.assertFalse(net.on_local_segment("255.255.255.255"))   # simulation: never
        finally:
            net.set_demo_network(None)
        self.assertTrue(net.on_local_segment("255.255.255.255"))  # nothing registered: allowed


NETSH = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Realtek 8852BE Wireless LAN WiFi 6 PCI-E NIC
    State                  : connected
    SSID                   : Moto Edge 50 Pro
    AP BSSID               : b6:9c:1a:eb:bb:bc
    BSSID                  : b6:9c:1a:eb:bb:bc
    Profile                : Moto Edge 50 Pro
"""

IW = """phy#0
\tInterface wlan0
\t\tifindex 3
\t\taddr d8:3a:dd:00:00:01
\t\tssid Moto Edge 50 Pro
\t\ttype managed
"""


class DemoNetwork(unittest.TestCase):
    """The demo only starts, and only broadcasts, on its own hotspot."""

    CFG = {"esp32": {"ssid": "Moto Edge 50 Pro"}, "dashboard": {"ip": "auto"},
           "nodes": [{"ip": "auto"}, {"ip": "auto"}]}

    def test_parse_wifi_tools(self):
        self.assertEqual(net._parse_netsh(NETSH), ["Moto Edge 50 Pro"])
        self.assertEqual(net._parse_netsh("    State : disconnected\n"), [])
        self.assertEqual(net._parse_iw(IW), ["Moto Edge 50 Pro"])
        self.assertEqual(net._parse_iw("phy#0\n\tInterface wlan0\n\t\ttype managed\n"), [])
        self.assertEqual(net._parse_nmcli("no:Other\nyes:Hive\\:Net\n"), ["Hive:Net"])

    def test_on_the_hotspot(self):
        self.assertIsNone(net.demo_network_problem(self.CFG, "10.229.175.4", ["Moto Edge 50 Pro"]))
        self.assertIsNone(net.demo_network_problem(self.CFG, "10.229.175.4", ["Moto Edge 50 Pro "]))

    def test_on_another_network(self):
        why = net.demo_network_problem(self.CFG, "172.16.45.60", ["VITC-EVENT"])
        self.assertIn("'VITC-EVENT'", why)
        self.assertIn("'Moto Edge 50 Pro'", why)
        self.assertIn("no Wi-Fi network", net.demo_network_problem(self.CFG, "192.168.1.9", []))

    def test_cannot_tell_or_nothing_to_compare(self):
        self.assertIsNone(net.demo_network_problem(self.CFG, "172.16.45.60", None))   # no Wi-Fi tools
        self.assertIsNone(net.demo_network_problem({"nodes": []}, "172.16.45.60", ["VITC-EVENT"]))

    def test_simulation_runs_anywhere(self):
        sim = {"esp32": {"ssid": "Moto Edge 50 Pro"}, "dashboard": {"ip": "127.0.0.1"},
               "nodes": [{"ip": "127.0.0.2"}, {"ip": "127.0.0.3"}]}
        self.assertIsNone(net.demo_network_problem(sim, "172.16.45.60", ["VITC-EVENT"]))

    def test_fixed_addresses_define_the_network(self):
        cfg = {"esp32": {"ssid": "HiveNet"}, "dashboard": {"ip": "10.42.0.1"}, "nodes": [{"ip": "auto"}]}
        self.assertIsNone(net.demo_network_problem(cfg, "10.42.0.17", ["Lab router"]))
        self.assertIsNotNone(net.demo_network_problem(cfg, "172.16.45.60", ["Lab router"]))

    def test_hive_up_check_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nodes.json")
            with open(path, "w") as f:
                json.dump({"nodes": [], "dashboard": {"ip": "auto"}}, f)
            up = [sys.executable, os.path.join(ROOT, "tools", "hive_up.py"), "--config", path]
            r = subprocess.run(up + ["--check-network"], capture_output=True, text=True, timeout=60)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "on the demo network"))
            r = subprocess.run(up, capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 2)   # no roles named


if __name__ == "__main__":
    unittest.main()
