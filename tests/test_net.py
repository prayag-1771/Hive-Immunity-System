"""UDP helpers: oversized datagrams must arrive whole, never crash the receive loop."""

import os
import socket
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))
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


if __name__ == "__main__":
    unittest.main()
