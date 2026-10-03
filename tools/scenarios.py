"""Scripted demo scenarios. SIMULATIONS ONLY, aimed at our own nodes on our own network.

Attacks must come from a machine (or loopback IP) that is not the hub, so this runs as a
small daemon on the attacker laptop and the dashboard buttons trigger it with signed
messages:

  python tools/scenarios.py serve                       # attacker laptop (LAN)
  python tools/scenarios.py serve --config config/local.json

It can also be driven by hand:

  python tools/scenarios.py attack --target 10.42.0.40
  python tools/scenarios.py cure --peers 10.42.0.40,10.42.0.12 --hub 10.42.0.1 --legit 10.42.0.12
  python tools/scenarios.py reset --peers 10.42.0.40,10.42.0.12

Safety: every packet goes to an address given on the command line / by the dashboard
(our nodes), to our LAN broadcast, or names a target inside 198.18.0.0/15 (reserved for
benchmarking, never routed on the internet) purely as data inside a vaccine.
"""

import argparse
import json
import os
import random
import select
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402

ATTACK_RATE = 50
ATTACK_SECONDS = 5
TRIGGERS = ("attack", "cure", "stop")


def make_trigger(admin_key, name, seq, **args):
    m = {"v": 1, "t": "trigger", "name": name, "seq": seq, "args": args}
    m["sig"] = hc.sign(admin_key, m)
    return m


def valid_trigger(m, admin_key, names):
    return (isinstance(m, dict) and set(m) == {"v", "t", "name", "seq", "args", "sig"}
            and m["t"] == "trigger" and m["name"] in names and hc.is_int(m["seq"])
            and isinstance(m["args"], dict) and hc.verify(admin_key, m))


class Attacker:
    def __init__(self, cfg, bind=None, report=None):
        self.cfg = cfg
        bind = bind or hc.static_ip(cfg["attacker"].get("ip")) or "0.0.0.0"
        self.sock = net.udp_socket(bind, 0, broadcast=True)
        self.my_ip = bind if bind != "0.0.0.0" else net.guess_lan_ip()
        self.keys = hc.issuer_keys(cfg)
        self.rng = random.Random()
        self.stop = threading.Event()
        self.report = report or (lambda kind, detail, target=None: print(f"[attacker] {kind}: {detail}", flush=True))
        self._rogue_seq = (int(time.time()) - 1_700_000_000) * 10

    # -- helpers

    def rogue_seq(self):
        self._rogue_seq = max(self._rogue_seq + 1, (int(time.time()) - 1_700_000_000) * 10)
        return self._rogue_seq

    def _send_vax(self, raw, peers):
        """One copy per node: unicast to the known nodes, broadcast only if none are known.

        Nodes silently drop a second copy of a *valid* vaccine, but every copy of a bad one
        is rejected (and counted) again, so sending both would inflate the counters.
        """
        port = self.cfg["network"]["vax_port"]
        for ip in list(peers) or net.broadcast_targets(self.cfg, self.my_ip)[:1]:
            net.send(self.sock, raw, (ip, port))

    def _junk(self, i):
        kind = i % 4
        if kind == 0:
            return bytes(self.rng.randrange(256) for _ in range(self.rng.randrange(20, 120)))
        if kind == 1:  # pretends to be the hub, but from the wrong address
            return hc.encode({"v": 1, "t": "cmd", "src": "hub", "dst": "*", "cmd": "light_on", "seq": i})
        if kind == 2:
            return b'{"v":1,"t":"cmd","cmd":"open_door","src":"x"}'
        return b"A" * 600  # oversized

    # -- scenarios

    def attack(self, target, seconds=ATTACK_SECONDS, rate=ATTACK_RATE):
        port = self.cfg["network"]["data_port"]
        self.stop.clear()
        self.report("attack_started", f"flooding {target} with malformed/unknown traffic "
                                      f"at {rate}/s for {seconds}s", self.my_ip)
        sent, start = 0, time.monotonic()
        while not self.stop.is_set():
            elapsed = time.monotonic() - start
            if elapsed >= seconds:
                break
            due = int(elapsed * rate) + 1
            while sent < due:
                net.send(self.sock, self._junk(sent), (target, port))
                sent += 1
            time.sleep(0.005)
        self.report("attack_finished", f"sent {sent} packets to {target}", self.my_ip)
        return sent

    def cure(self, peers, hub_ip=None, legit_ip=None, pause=1.5):
        """Attack the cure: every way of abusing the vaccine channel, one after another."""
        rogue_key = self.keys["rogue"]
        fake_key = "ee" * 32
        legit_ip = legit_ip or (peers[0] if peers else "198.18.0.10")
        steps = []

        first = self.rogue_seq()
        steps.append(("single_report", f"rogue device asks everyone to block a healthy device {legit_ip}",
                      hc.encode(hc.make_vax("rogue", rogue_key, first, legit_ip, 300, "flood"))))
        steps.append(("forged", "vaccine claiming to be lapA, signed with a made-up key",
                      hc.encode(hc.make_vax("lapA", fake_key, 999_999_999, "198.18.0.66", 300, "flood"))))
        tampered = hc.make_vax("rogue", rogue_key, self.rogue_seq(), "198.18.0.66", 300, "flood")
        tampered["target"] = legit_ip
        steps.append(("tampered", f"valid vaccine with its target edited to {legit_ip} after signing",
                      hc.encode(tampered)))
        steps.append(("oversized", "400-byte vaccine stuffed with junk",
                      b'{"v":1,"t":"vax","issuer":"rogue","reason":"' + b"x" * 360 + b'"}'))
        if hub_ip:
            steps.append(("protected", f"vaccine trying to block the hub {hub_ip}",
                          hc.encode(hc.make_vax("rogue", rogue_key, self.rogue_seq(), hub_ip, 300, "flood"))))
        steps.append(("replay", "re-sends an older vaccine (lower sequence number)",
                      hc.encode(hc.make_vax("rogue", rogue_key, first - 1, "198.18.0.77", 300, "flood"))))

        self.stop.clear()
        for name, detail, raw in steps:
            if self.stop.is_set():
                return
            self.report("cure_step", f"{name}: {detail}")
            self._send_vax(raw, peers)
            time.sleep(pause)
        self.report("cure_step", "flood: rogue device sends 6 valid vaccines in one second")
        for i in range(6):
            raw = hc.encode(hc.make_vax("rogue", rogue_key, self.rogue_seq(), f"198.18.1.{i + 1}", 300, "flood"))
            self._send_vax(raw, peers)
            time.sleep(0.15)
        self.report("cure_finished", "attack-the-cure sequence finished")

    def reset(self, peers):
        port = self.cfg["network"]["data_port"]
        raw = hc.encode(hc.make_ctrl(self.cfg["admin_key"], "reset", int(time.time() * 1000)))
        for ip in peers:
            net.send(self.sock, raw, (ip, port))


def serve(cfg, bind=None):
    """Attacker daemon: waits for signed triggers from the dashboard."""
    port = cfg["network"]["attacker_port"]
    sock = net.udp_socket(bind or hc.static_ip(cfg["attacker"].get("ip")) or "0.0.0.0", port, broadcast=True)
    dash = {"ip": hc.static_ip(cfg["dashboard"].get("ip"))}
    status_port = cfg["network"]["status_port"]

    def to_dashboard(msg):
        targets = [dash["ip"]] if dash["ip"] else net.broadcast_targets(cfg, attacker.my_ip)
        for ip in targets:
            net.send(sock, msg, (ip, status_port))

    def report(kind, detail, target=None):
        print(f"{time.strftime('%H:%M:%S')} [attacker] {kind}: {detail}", flush=True)
        msg = {"v": 1, "t": "event", "node": "attacker", "kind": kind, "detail": detail, "ts": round(time.time(), 3)}
        if target:
            msg["target"] = target
        to_dashboard(msg)

    attacker = Attacker(cfg, bind, report)
    last_seq = -1
    worker = None
    next_hello = 0.0
    print(f"attacker daemon on {attacker.my_ip}:{port} -- simulations against our own nodes only", flush=True)
    while True:
        now = time.monotonic()
        if now >= next_hello:
            next_hello = now + 2.0
            to_dashboard({"v": 1, "t": "hello", "role": "attacker", "ip": attacker.my_ip,
                          "busy": bool(worker and worker.is_alive())})
        select.select([sock], [], [], 0.5)
        for data, ip in net.recv_all(sock):
            try:
                m = json.loads(data)
            except ValueError:
                continue
            if not valid_trigger(m, cfg["admin_key"], TRIGGERS) or m["seq"] <= last_seq:
                continue
            last_seq = m["seq"]
            dash["ip"] = dash["ip"] or ip
            if m["name"] == "stop":
                attacker.stop.set()
                continue
            if worker and worker.is_alive():
                attacker.stop.set()
                worker.join(2.0)
            a = m["args"]
            if m["name"] == "attack":
                fn, fargs = attacker.attack, (a["target"],)
            else:
                fn, fargs = attacker.cure, (a.get("peers", []), a.get("hub"), a.get("legit"))
            worker = threading.Thread(target=fn, args=fargs, daemon=True)
            worker.start()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=("serve", "attack", "cure", "reset"))
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--bind", help="source address (default: attacker ip from config)")
    ap.add_argument("--target", help="attack: node IP")
    ap.add_argument("--peers", default="", help="comma list of node IPs")
    ap.add_argument("--hub", help="cure: hub IP (for the protected-target case)")
    ap.add_argument("--legit", help="cure: a healthy device IP the rogue tries to get blocked")
    ap.add_argument("--seconds", type=float, default=ATTACK_SECONDS)
    ap.add_argument("--rate", type=int, default=ATTACK_RATE)
    args = ap.parse_args()
    cfg = hc.load_config(args.config)
    peers = [p for p in args.peers.split(",") if p]
    try:
        if args.command == "serve":
            serve(cfg, args.bind)
        attacker = Attacker(cfg, args.bind)
        if args.command == "attack":
            if not args.target:
                ap.error("attack needs --target")
            attacker.attack(args.target, args.seconds, args.rate)
        elif args.command == "cure":
            attacker.cure(peers, args.hub, args.legit)
        elif args.command == "reset":
            attacker.reset(peers)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
