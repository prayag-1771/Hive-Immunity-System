"""Normal-traffic hub: the "smart home app" that talks to every node all day.

Each node receives about `rate` commands per second (random, so the baseline has a real
spread): mostly pings, a light toggle every few seconds, an occasional status request.
The dashboard runs a Hub in-process; it can also run alone:

  python agent/hub.py --config config/local.json
  python agent/hub.py --target lapA=10.42.0.12 --target esp32=10.42.0.40
"""

import argparse
import json
import os
import random
import select
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402


class Hub:
    def __init__(self, cfg, rate=3.0, tick=0.05):
        self.cfg = cfg
        self.port = cfg["network"]["data_port"]
        self.rate = rate
        self.tick = tick
        self.sock = net.udp_socket(hc.static_ip(cfg["hub"].get("ip")) or "0.0.0.0", 0)
        self.targets = {e["node_id"]: e["ip"] for e in cfg["nodes"] if hc.static_ip(e.get("ip"))}
        self.lights = {}
        self.next_toggle = {}
        self.seq = 0
        self.paused = False
        self.rng = random.Random()
        self._lock = threading.Lock()

    def set_target(self, node_id, ip):
        with self._lock:
            self.targets[node_id] = ip

    def _command(self, node_id, now):
        if now >= self.next_toggle.get(node_id, 0.0):
            self.next_toggle[node_id] = now + self.rng.uniform(3.0, 6.0)
            self.lights[node_id] = not self.lights.get(node_id, False)
            return "light_on" if self.lights[node_id] else "light_off"
        return "status" if self.rng.random() < 0.1 else "ping"

    def step(self, now):
        if self.paused:
            return
        with self._lock:
            targets = list(self.targets.items())
        for node_id, ip in targets:
            if self.rng.random() < self.rate * self.tick:
                self.seq += 1
                msg = {"v": 1, "t": "cmd", "src": "hub", "dst": node_id,
                       "cmd": self._command(node_id, now), "seq": self.seq}
                net.send(self.sock, msg, (ip, self.port))

    def run(self, stop=None):
        while stop is None or not stop.is_set():
            self.step(time.monotonic())
            time.sleep(self.tick)

    def start(self):
        t = threading.Thread(target=self.run, name="hub", daemon=True)
        t.start()
        return t


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--target", action="append", default=[], metavar="NODE=IP")
    ap.add_argument("--rate", type=float, default=3.0, help="commands per second per node")
    args = ap.parse_args()
    cfg = hc.load_config(args.config)
    net.set_demo_network(cfg)
    hub = Hub(cfg, args.rate)
    for t in args.target:
        node_id, ip = t.split("=", 1)
        hub.set_target(node_id, ip)

    # Standalone: discover nodes from their status packets (the dashboard does this otherwise).
    listen = net.udp_socket(hc.static_ip(cfg["dashboard"].get("ip")) or "0.0.0.0",
                            cfg["network"]["status_port"])
    hub.start()
    print(f"hub sending ~{args.rate}/s to {hub.targets or 'nodes as they appear'}", flush=True)
    try:
        while True:
            ready, _, _ = select.select([listen], [], [], 1.0)
            for data, ip in net.recv_all(listen):
                try:
                    msg = json.loads(data)
                except ValueError:
                    continue
                known = {e["node_id"] for e in cfg["nodes"]}
                if msg.get("t") == "status" and msg.get("node") in known and msg["node"] not in hub.targets:
                    hub.set_target(msg["node"], ip)
                    print(f"hub: found {msg['node']} at {ip}", flush=True)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
