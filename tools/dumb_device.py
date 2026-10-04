"""Simulated dumb Wi-Fi bulb: it cannot run Hive, so only the gateway can protect it.

Normal: one small telemetry message to the gateway every 2-5 s ("I'm a bulb").
Infected (dashboard button): ~40 messages/s naming many destinations in 198.18.0.0/15,
like a bot scanning or flooding. The destinations are DATA inside the message only:
every packet is sent to the gateway's sink port and nowhere else.

  python tools/dumb_device.py                          # on the attacker/bulb laptop
  python tools/dumb_device.py --config config/local.json
"""

import argparse
import json
import os
import random
import select
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402
from scenarios import valid_trigger  # noqa: E402

INFECTED_RATE = 40


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--bind")
    ap.add_argument("--gateway", help="gateway IP (default: config, else broadcast)")
    ap.add_argument("--name", help="device name shown on the dashboard")
    args = ap.parse_args()
    cfg = hc.load_config(args.config)
    name = args.name or cfg["dumb"].get("name", "bulb")
    bind = args.bind or hc.static_ip(cfg["dumb"].get("ip")) or "0.0.0.0"
    sock = net.udp_socket(bind, cfg["network"]["dumb_port"], broadcast=True)
    my_ip = bind if bind != "0.0.0.0" else net.guess_lan_ip()
    gw = args.gateway or hc.static_ip(hc.node_entry(cfg, "gateway").get("ip"))
    gateways = [gw] if gw else net.broadcast_targets(cfg, my_ip)
    dash = hc.static_ip(cfg["dashboard"].get("ip"))
    sink, status_port = cfg["network"]["sink_port"], cfg["network"]["status_port"]
    rng = random.Random()

    infected, seq, last_trigger = False, 0, -1
    next_tele, next_hello = time.monotonic() + 1.0, 0.0
    print(f"{name} at {my_ip}: telemetry to {gateways}:{sink}", flush=True)
    try:
        while True:
            now = time.monotonic()
            if now >= next_hello:
                next_hello = now + 2.0
                # The dashboard needs our address for its "infect" button; the gateway may be a
                # different machine (e.g. the Pi), so say hello by broadcast until we know it.
                for ip in ([dash] if dash else net.broadcast_targets(cfg, my_ip)[:1]):
                    net.send(sock, {"v": 1, "t": "hello", "role": "dumb", "ip": my_ip, "busy": infected},
                             (ip, status_port))
            if now >= next_tele:
                seq += 1
                if infected:
                    dst = f"198.{18 + rng.randrange(2)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
                    next_tele = now + 1.0 / INFECTED_RATE
                else:
                    dst = "198.18.0.1"   # stands in for the bulb's one vendor cloud endpoint
                    next_tele = now + rng.uniform(2.0, 5.0)
                for ip in gateways:
                    net.send(sock, {"v": 1, "t": "tele", "dev": name, "dst": dst, "seq": seq}, (ip, sink))
            select.select([sock], [], [], max(0.0, min(next_tele, next_hello) - time.monotonic()))
            for data, ip in net.recv_all(sock):
                try:
                    m = json.loads(data)
                except ValueError:
                    continue
                if valid_trigger(m, cfg["admin_key"], ("infect", "heal")) and m["seq"] > last_trigger:
                    last_trigger = m["seq"]
                    dash = dash or ip
                    infected = m["name"] == "infect"
                    print(f"{time.strftime('%H:%M:%S')} {name}: {'INFECTED - flooding' if infected else 'healed - normal'}",
                          flush=True)
                    next_tele = time.monotonic()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
