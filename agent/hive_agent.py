"""Run one Hive immune node on this machine.

  python agent/hive_agent.py --node lapA                    # real LAN, config/nodes.json
  python agent/hive_agent.py --node lapB --config config/local.json   # one-laptop sim

The node listens for hub commands on the data port and vaccines on the vax port, learns
its normal traffic, quarantines itself on an anomaly and broadcasts signed vaccines.
Status (1 Hz) and events go to the dashboard over UDP.
"""

import argparse
import json
import os
import select
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402

MODEL_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.json")


class Agent:
    def __init__(self, cfg, node_id, bind=None, detector="auto", fresh=False, quiet=False):
        self.cfg = cfg
        self.quiet = quiet
        entry = hc.node_entry(cfg, node_id)
        port = cfg["network"]
        static = hc.static_ip(entry.get("ip"))
        self.bind_ip = bind or static or "0.0.0.0"
        self.my_ip = static or (bind if bind and bind != "0.0.0.0" else net.guess_lan_ip())
        self.dash_ip = hc.static_ip(cfg["dashboard"].get("ip"))
        self.bcast = net.broadcast_targets(cfg, self.my_ip)
        self.peers = net.peer_ips(cfg, exclude=(self.my_ip,))

        cfg_name = os.path.splitext(os.path.basename(cfg["_path"]))[0]
        self.state_dir = os.path.join(net.ROOT, "data", "state", cfg_name)
        self.state_path = os.path.join(self.state_dir, f"{node_id}.json")
        self.window_log = os.path.join(net.ROOT, "data", "windows", f"{cfg_name}-{node_id}.jsonl")
        saved = {} if fresh else self._load_state()

        self.node = hc.HiveNode(
            node_id, entry["key"], hc.issuer_keys(cfg), cfg["admin_key"], cfg["demo"], cfg["quorum"],
            my_ip=self.my_ip, hub_ip=hc.static_ip(cfg["hub"].get("ip")),
            protected=cfg.get("protected", []), detector=self._detector(detector),
            baseline=hc.Baseline.from_dict(saved["baseline"]) if saved.get("baseline") else None,
            vax_seq=saved.get("vax_seq", 0), now=time.monotonic(),
            kind="python" if entry.get("kind", "python") == "python" else entry["kind"])

        self.data_sock = net.udp_socket(self.bind_ip, port["data_port"])
        self.vax_sock = net.udp_socket(self.bind_ip, port["vax_port"], broadcast=True)
        self.status_port = port["status_port"]
        self.vax_port = port["vax_port"]
        self.next_status = 0.0
        self.last_score_logged = None

    # -- persistence

    def _load_state(self):
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _save_state(self):
        os.makedirs(self.state_dir, exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"baseline": self.node.baseline.to_dict() if self.node.baseline else None,
                       "vax_seq": self.node.vax_seq}, f)
        os.replace(tmp, self.state_path)

    def _detector(self, choice):
        threshold = self.cfg["demo"]["threshold"]
        if choice in ("auto", "autoencoder") and os.path.exists(MODEL_JSON):
            return hc.AutoencoderDetector.load(MODEL_JSON)
        if choice == "autoencoder":
            raise SystemExit(f"--detector autoencoder needs {MODEL_JSON}; run tools/train_autoencoder.py")
        return hc.ZScoreDetector(threshold)

    # -- outputs

    def log(self, text):
        if not self.quiet:
            print(f"{time.strftime('%H:%M:%S')} [{self.node.node_id}] {text}", flush=True)

    def _status_addr(self):
        ip = self.dash_ip or self.node.hub_ip
        if ip:
            return [(ip, self.status_port)]
        return [(b, self.status_port) for b in self.bcast]

    def _flush(self, now):
        events, vaccines = self.node.drain()
        for v in vaccines:
            raw = hc.encode(v)
            for ip in self.bcast + self.peers:
                net.send(self.vax_sock, raw, (ip, self.vax_port))
        for e in events:
            self.log(f"{e['kind']}: {e['detail']}")
            msg = {"v": 1, "t": "event", "node": self.node.node_id, "kind": e["kind"],
                   "detail": e["detail"], "ts": round(time.time() - (now - e["mono"]), 3)}
            if e.get("target"):
                msg["target"] = e["target"]
            for addr in self._status_addr():
                net.send(self.vax_sock, msg, addr)
        if self.node.dirty:
            self.node.dirty = False
            self._save_state()

    def _status(self, now):
        msg = self.node.status(now, time.time())
        msg["ip"] = self.my_ip
        for addr in self._status_addr():
            net.send(self.vax_sock, msg, addr)

    def _log_window(self):
        n = self.node
        if n.state != "healthy" or n.baseline is None or n.score > n.detector.threshold:
            return
        os.makedirs(os.path.dirname(self.window_log), exist_ok=True)
        with open(self.window_log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"f": [round(x, 4) for x in n.features],
                                "z": [round(x, 4) for x in n.baseline.z(n.features)]}) + "\n")

    # -- loop

    def run(self):
        n = self.node
        self.log(f"up on {self.bind_ip} (my ip {self.my_ip}), detector {n.detector.name}, "
                 f"state {n.state}, vaccines to {self.bcast + self.peers or 'nobody'}")
        window_start = n.window_start
        while True:
            now = time.monotonic()
            wake = min(self.next_status, n.window_start + n.demo["window_seconds"])
            timeout = min(0.1, max(0.0, wake - now))
            ready, _, _ = select.select([self.data_sock, self.vax_sock], [], [], timeout)
            now = time.monotonic()
            for sock in ready:
                handler = n.on_data if sock is self.data_sock else n.on_vax
                for data, ip in net.recv_all(sock):
                    handler(ip, data, now)
            n.tick(now)
            if n.window_start != window_start:
                window_start = n.window_start
                self._log_window()
            self._flush(now)
            if now >= self.next_status:
                self.next_status = now + 1.0
                self._status(now)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--node", required=True, help="node_id from the config")
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--bind", help="override the bind address")
    ap.add_argument("--detector", choices=("auto", "zscore", "autoencoder"), default="auto",
                    help="auto = autoencoder if agent/model.json exists, else z-score")
    ap.add_argument("--fresh", action="store_true", help="ignore the saved baseline and relearn")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    agent = Agent(hc.load_config(args.config), args.node, args.bind, args.detector, args.fresh, args.quiet)
    try:
        agent.run()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
