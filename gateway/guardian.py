"""Gateway guardian: protects dumb devices (bulbs, plugs, cameras) that cannot run Hive.

Runs on the router/gateway. Learns each device's normal behaviour from the traffic it
sends through the gateway -- in the demo, the telemetry a device sends to the gateway's
sink port -- and quarantines a device that starts misbehaving:

  * always: app-level quarantine (the gateway stops accepting/relaying its traffic)
  * with --nft on Linux: the device IP goes into an nftables set that drops its
    forwarded traffic (see nft_rules.nft); in a real OpenWrt router this is the same rule

It also broadcasts a signed vaccine so Hive nodes are warned about the device.

  python gateway/guardian.py                        # LAN demo, app-level quarantine
  sudo python3 gateway/guardian.py --nft            # Linux gateway with nftables
"""

import argparse
import json
import os
import select
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402

FLOORS = (1.0, 1.0)            # msgs/s, distinct destinations/s
NFT_SET = ("inet", "hive", "quarantine")


class Device:
    def __init__(self, ip, name, now):
        self.ip = ip
        self.name = name
        self.baseline = hc.Baseline(FLOORS)
        self.learn_start = now
        self.state = "learning"
        self.count = 0
        self.dsts = set()
        self.features = [0.0, 0.0]
        self.score = 0.0
        self.hot = 0
        self.dropped = 0

    def take_window(self, seconds):
        f = [self.count / seconds, len(self.dsts) / seconds]
        self.count, self.dsts = 0, set()
        return f


class Guardian:
    def __init__(self, cfg, bind=None, use_nft=False, dashboard=None):
        self.cfg = cfg
        self.demo = cfg["demo"]
        entry = hc.node_entry(cfg, "gateway")
        self.key = entry["key"]
        bind = bind or hc.static_ip(entry.get("ip")) or "0.0.0.0"
        self.my_ip = bind if bind != "0.0.0.0" else net.guess_lan_ip()
        self.sock = net.udp_socket(bind, cfg["network"]["sink_port"], broadcast=True)
        self.dash = dashboard or hc.static_ip(cfg["dashboard"].get("ip"))
        self.bcast = net.broadcast_targets(cfg, self.my_ip)
        self.peers = net.peer_ips(cfg, exclude=(self.my_ip,))
        self.use_nft = use_nft
        self.devices = {}
        self.last_ctrl = -1
        self.window_start = time.monotonic()
        cfg_name = os.path.splitext(os.path.basename(cfg["_path"]))[0]
        self.state_path = os.path.join(ROOT, "data", "state", cfg_name, "gateway.json")
        self.vax_seq = self._load_seq()

    # -- persistence of the vaccine sequence number (replay protection survives restarts)

    def _load_seq(self):
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                return json.load(f).get("vax_seq", 0)
        except (OSError, ValueError):
            return 0

    def _save_seq(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump({"vax_seq": self.vax_seq}, f)

    # -- reporting

    def log(self, text):
        print(f"{time.strftime('%H:%M:%S')} [gateway] {text}", flush=True)

    def _to_dashboard(self, msg):
        # One copy: the dashboard's address once known (learned from its signed control
        # messages), else a single broadcast form, so the dashboard never logs duplicates.
        port = self.cfg["network"]["status_port"]
        for ip in ([self.dash] if self.dash else self.bcast[:1]):
            net.send(self.sock, msg, (ip, port))

    def event(self, kind, detail, target=None):
        self.log(f"{kind}: {detail}")
        msg = {"v": 1, "t": "event", "node": "gateway", "kind": kind, "detail": detail,
               "ts": round(time.time(), 3)}
        if target:
            msg["target"] = target
        self._to_dashboard(msg)

    def status(self, now):
        for d in self.devices.values():
            learn = min(1.0, (now - d.learn_start) / self.demo["learn_seconds"]) if d.state == "learning" else 1.0
            self._to_dashboard({
                "v": 1, "t": "status", "node": d.name, "kind": "dumb", "state": d.state, "ip": d.ip,
                "score": round(d.score, 2), "thr": self.demo["threshold"],
                "features": [round(x, 2) for x in d.features], "dropped": d.dropped,
                "learn": round(learn, 2), "by": self.my_ip, "nft": self.use_nft, "ts": round(time.time(), 3)})

    # -- enforcement

    def _nft(self, *args):
        if not self.use_nft:
            return
        try:
            subprocess.run(["nft", *args], check=True, capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as e:
            self.log(f"nft {' '.join(args)} failed: {e}")

    def quarantine(self, d, now):
        d.state = "quarantined"
        self._nft("add", "element", *NFT_SET, "{", d.ip, "}")
        how = "nftables set + app-level" if self.use_nft else "app-level (a firewall rule on a real router)"
        self.event("quarantine", f"{d.name} ({d.ip}) quarantined by gateway: score {d.score:.1f}, "
                                 f"{d.features[0]:.0f} msgs/s to {d.features[1]:.0f} destinations/s; {how}", d.ip)
        self.vax_seq += 1
        self._save_seq()
        vax = hc.encode(hc.make_vax("gateway", self.key, self.vax_seq, d.ip, int(self.demo["vax_ttl_s"]), "flood"))
        port = self.cfg["network"]["vax_port"]
        for ip in self.bcast + self.peers:
            net.send(self.sock, vax, (ip, port))
        self.event("vax_issued", f"block {d.ip} (flood), seq {self.vax_seq}", d.ip)

    def reset(self, relearn=False):
        self._nft("flush", "set", *NFT_SET)
        now = time.monotonic()
        for ip, d in list(self.devices.items()):
            if relearn:
                self.devices[ip] = Device(ip, d.name, now)
            else:
                d.state = "healthy" if d.baseline.n else "learning"
                d.hot, d.dropped, d.score = 0, 0, 0.0
        self.event("heal", "relearning devices" if relearn else "quarantine lifted by operator")

    # -- inbound

    def on_packet(self, ip, raw, now):
        m = hc.parse(raw)
        if m is None:
            return
        if m["t"] == "ctrl":
            if hc.valid_ctrl(m) and m["seq"] > self.last_ctrl and hc.verify(self.cfg["admin_key"], m):
                self.last_ctrl = m["seq"]
                self.dash = self.dash or ip
                self.reset(relearn=m["cmd"] == "relearn")
            return
        if m["t"] != "tele":
            return
        d = self.devices.get(ip)
        if d is None:
            name = m.get("dev") if isinstance(m.get("dev"), str) and hc.NODE_ID_RE.match(m["dev"]) else ip
            d = self.devices[ip] = Device(ip, name, now)
            self.log(f"new device {name} at {ip}: learning its normal behaviour")
        if d.state == "quarantined":
            d.dropped += 1
            return
        d.count += 1
        dst = m.get("dst")
        d.dsts.add(dst if isinstance(dst, str) else "?")

    def tick(self, now):
        elapsed = now - self.window_start
        if elapsed < self.demo["window_seconds"]:
            return
        self.window_start = now
        for d in self.devices.values():
            d.features = d.take_window(elapsed)
            if d.state == "learning":
                d.baseline.add(d.features)
                if now - d.learn_start >= self.demo["learn_seconds"]:
                    d.state = "healthy"
                    self.event("learned", f"{d.name}: baseline from {d.baseline.n} windows "
                                          f"({d.baseline.mean[0]:.2f} msgs/s normal)")
                continue
            if d.state == "quarantined":
                continue
            d.score = max(abs(z) for z in d.baseline.z(d.features))
            d.hot = d.hot + 1 if d.score > self.demo["threshold"] else 0
            if d.hot >= self.demo["consecutive"]:
                self.quarantine(d, now)

    def run(self):
        self.log(f"guarding dumb devices on {self.my_ip}:{self.cfg['network']['sink_port']}"
                 f" (nftables {'on' if self.use_nft else 'off'})")
        if self.use_nft:
            self._nft("flush", "set", *NFT_SET)
        next_status = 0.0
        while True:
            select.select([self.sock], [], [], 0.1)
            now = time.monotonic()
            for data, ip in net.recv_all(self.sock):
                self.on_packet(ip, data, now)
            self.tick(now)
            if now >= next_status:
                next_status = now + 1.0
                self.status(now)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--bind")
    ap.add_argument("--dashboard", help="dashboard IP (default: config, else broadcast)")
    ap.add_argument("--nft", action="store_true", help="also enforce with nftables (Linux, root)")
    args = ap.parse_args()
    if args.nft and not sys.platform.startswith("linux"):
        raise SystemExit("--nft needs a Linux gateway")
    try:
        Guardian(hc.load_config(args.config), args.bind, args.nft, args.dashboard).run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
