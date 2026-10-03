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


if __name__ == "__main__":
    unittest.main()
