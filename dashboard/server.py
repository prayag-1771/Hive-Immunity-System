"""Hive dashboard: live node tiles, event log, scenario buttons. Standard library only.

  python dashboard/server.py                          # LAN demo (config/nodes.json)
  python dashboard/server.py --config config/local.json

Runs the normal-traffic hub in-process, listens for node status/events on the status port,
serves index.html, and pushes live state to the browser with Server-Sent Events.
"""

import argparse
import collections
import json
import os
import queue
import select
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402
from hub import Hub  # noqa: E402

INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
OFFLINE_AFTER = 3.5
BLOCK_KINDS = ("vax_issued", "vax_adopted")


def label_for(entry):
    if entry.get("label"):
        return entry["label"]
    nid = entry["node_id"]
    if nid.lower().startswith("lap") and len(nid) > 3:
        return "Laptop " + nid[3:]
    return nid.upper() if nid.lower().startswith("esp") else nid


class Dashboard:
    def __init__(self, cfg, run_hub=True):
        self.cfg = cfg
        self.lock = threading.Lock()
        port = cfg["network"]
        self.sock = net.udp_socket(hc.static_ip(cfg["dashboard"].get("ip")) or "0.0.0.0",
                                   port["status_port"], broadcast=True)
        self.my_ip = hc.static_ip(cfg["dashboard"].get("ip")) or net.guess_lan_ip()
        self.hub_ip = hc.static_ip(cfg["hub"].get("ip")) or self.my_ip
        self.hub = Hub(cfg) if run_hub else None
        self.order = [e["node_id"] for e in cfg["nodes"]]
        self.entries = {e["node_id"]: e for e in cfg["nodes"]}
        self.nodes = {nid: {"status": None, "ip": hc.static_ip(e.get("ip")), "seen": 0.0}
                      for nid, e in self.entries.items()}
        self.gateway_ip = next((hc.static_ip(e.get("ip")) for e in cfg["issuers"]
                                if e["node_id"] == "gateway"), None)
        self.bulb = {"status": None, "seen": 0.0}
        self.peers = {
            "attacker": {"ip": hc.static_ip(cfg["attacker"].get("ip")), "seen": 0.0, "busy": False},
            "dumb": {"ip": hc.static_ip(cfg["dumb"].get("ip")), "seen": 0.0, "busy": False},
        }
        self.events = collections.deque(maxlen=200)
        self.subscribers = []
        self.defenses = {}
        self.trigger_seq = int(time.time() * 1000)
        # Every event is stamped with the dashboard's own clock on arrival: devices' clocks
        # can disagree (an offline Pi has no battery-backed clock, the ESP32 has none).
        self.clock = time.time
        self._reset_immunity()

    # -- immunity timer

    def _reset_immunity(self):
        self.immunity = {"target": None, "t0": None, "t1": None, "nodes": {}, "instant": {}}

    def _online(self, nid, now):
        return now - self.nodes[nid]["seen"] < OFFLINE_AFTER

    def _check_immune(self):
        im = self.immunity
        if im["t0"] is None or im["t1"] is not None:
            return
        now = time.monotonic()
        online = [n for n in self.order if self._online(n, now)]
        if online and all(n in im["nodes"] for n in online):
            im["t1"] = max(ts for ts, _ in im["nodes"].values())

    def _track(self, node, msg):
        im, kind, target = self.immunity, msg["kind"], msg.get("target")
        if node == "attacker" and kind == "attack_started" and im["t1"] is None:
            if im["t0"] is None or im["target"] != target:
                self._reset_immunity()
                im = self.immunity
                im["t0"], im["target"] = msg["ts"], target
        if node in self.nodes and target and target == im["target"]:
            if kind in BLOCK_KINDS and node not in im["nodes"]:
                im["nodes"][node] = (msg["ts"], "adopted" if kind == "vax_adopted" else "detected")
            if kind == "blocked_first_packet" and im["nodes"].get(node, (0, ""))[1] == "adopted":
                im["instant"][node] = msg["ts"]
        if kind == "vax_rejected":
            self.defenses[msg["detail"].split(":")[0]] = msg["ts"]
        if kind == "vax_pending" and "from rogue" in msg["detail"]:
            self.defenses["quorum"] = msg["ts"]
        self._check_immune()

    # -- inbound UDP

    def listen(self):
        while True:
            select.select([self.sock], [], [], 0.5)
            for data, ip in net.recv_all(self.sock):
                try:
                    msg = json.loads(data)
                except ValueError:
                    continue
                if isinstance(msg, dict):
                    self._on_msg(msg, ip)

    def _on_msg(self, msg, ip):
        now = time.monotonic()
        t = msg.get("t")
        with self.lock:
            if t == "status":
                node = msg.get("node")
                if node in self.nodes:
                    rec = self.nodes[node]
                    rec.update(status=msg, ip=ip, seen=now)
                    if self.hub:
                        self.hub.set_target(node, ip)
                    target = self.immunity["target"]
                    if target and target in msg.get("blocklist", []) and node not in self.immunity["nodes"]:
                        self.immunity["nodes"][node] = (self.clock(), "adopted")
                    self._check_immune()
                elif msg.get("kind") == "dumb":
                    self.bulb.update(status=msg, seen=now)
                    self.gateway_ip = self.gateway_ip or ip
            elif t == "hello" and msg.get("role") in self.peers:
                self.peers[msg["role"]].update(ip=ip, seen=now, busy=bool(msg.get("busy")))
            elif t == "event" and isinstance(msg.get("kind"), str):
                ev = {"node": str(msg.get("node", "?")), "kind": msg["kind"],
                      "detail": str(msg.get("detail", ""))[:200], "ts": self.clock(),
                      "target": msg.get("target")}
                self.events.append(ev)
                self._track(ev["node"], ev)
                self._publish("log", ev)

    # -- outbound

    def _publish(self, kind, payload):
        for q in list(self.subscribers):
            try:
                q.put_nowait((kind, payload))
            except queue.Full:
                pass

    def note(self, detail, kind="operator"):
        ev = {"node": "dashboard", "kind": kind, "detail": detail, "ts": time.time(), "target": None}
        with self.lock:
            self.events.append(ev)
        self._publish("log", ev)

    def _trigger(self, role, name, **args):
        peer = self.peers[role]
        port = self.cfg["network"]["attacker_port" if role == "attacker" else "dumb_port"]
        if not peer["ip"]:
            return False, f"{role} is not connected (start tools/{'scenarios.py serve' if role == 'attacker' else 'dumb_device.py'})"
        self.trigger_seq = max(self.trigger_seq + 1, int(time.time() * 1000))
        m = {"v": 1, "t": "trigger", "name": name, "seq": self.trigger_seq, "args": args}
        m["sig"] = hc.sign(self.cfg["admin_key"], m)
        net.send(self.sock, m, (peer["ip"], port))
        return True, f"{name} sent to {role}"

    def _ctrl(self, cmd):
        self.trigger_seq = max(self.trigger_seq + 1, int(time.time() * 1000))
        raw = hc.encode(hc.make_ctrl(self.cfg["admin_key"], cmd, self.trigger_seq))
        port = self.cfg["network"]
        ips = {rec["ip"] for rec in self.nodes.values() if rec["ip"]}
        for ip in ips:
            net.send(self.sock, raw, (ip, port["data_port"]))
        if self.gateway_ip:
            net.send(self.sock, raw, (self.gateway_ip, port["sink_port"]))
        return len(ips)

    def node_ips(self):
        return [self.nodes[n]["ip"] for n in self.order if self.nodes[n]["ip"]]

    def scenario(self, parts):
        name = parts[0] if parts else ""
        if name == "attack" and len(parts) == 2 and parts[1] in self.nodes:
            ip = self.nodes[parts[1]]["ip"]
            if not ip:
                return False, f"{parts[1]} has not reported in yet"
            ok, msg = self._trigger("attacker", "attack", target=ip)
            if ok:
                self.note(f"pressed: attack {label_for(self.entries[parts[1]])} ({ip})", "scenario")
            return ok, msg
        if name == "cure":
            ips = self.node_ips()
            legit = ips[-1] if ips else None
            ok, msg = self._trigger("attacker", "cure", peers=ips, hub=self.hub_ip, legit=legit)
            if ok:
                self.note("pressed: attack the cure (poisoned vaccines)", "scenario")
            return ok, msg
        if name == "stop":
            return self._trigger("attacker", "stop")
        if name in ("infect_bulb", "heal_bulb"):
            ok, msg = self._trigger("dumb", "infect" if name == "infect_bulb" else "heal")
            if ok and name == "infect_bulb":
                self.note("pressed: infect the dumb bulb", "scenario")
            return ok, msg
        return False, f"unknown scenario {'/'.join(parts)}"

    def reset(self):
        n = self._ctrl("reset")
        if self.peers["attacker"]["ip"]:
            self._trigger("attacker", "stop")
        if self.peers["dumb"]["ip"]:
            self._trigger("dumb", "heal")
        with self.lock:
            self._reset_immunity()
            self.defenses = {}
        self.note(f"reset: everyone back to healthy ({n} node(s))", "reset")
        return True, "reset sent"

    def relearn(self):
        n = self._ctrl("relearn")
        self.note(f"relearn: {n} node(s) learning normal traffic again", "reset")
        return True, "relearn sent"

    # -- explain (optional local open model)

    def explain(self):
        with self.lock:
            recent = list(self.events)[-40:]
            states = {n: (self.nodes[n]["status"] or {}).get("state", "offline") for n in self.order}
        incident = {"nodes": states, "events": [{k: e[k] for k in ("node", "kind", "detail")} for e in recent]}
        ex = self.cfg.get("explain", {})
        url = ex.get("url", "http://127.0.0.1:11434") + "/api/generate"
        prompt = ("You are explaining a security incident to non-experts watching a live demo of a "
                  "peer-to-peer immune system for IoT devices. In 4 short sentences, say what attacked, "
                  "which devices detected it, how the others became immune via signed vaccines, and "
                  "whether any poisoned vaccines were rejected. Incident JSON:\n" + json.dumps(incident))
        body = json.dumps({"model": ex.get("model", "gemma4"), "prompt": prompt, "stream": False}).encode()
        try:
            req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=ex.get("timeout_s", 25)) as r:
                text = json.loads(r.read()).get("response", "").strip()
            if text:
                return {"source": f"{ex.get('model', 'gemma4')} (local)", "text": text}
        except Exception:
            pass
        return {"source": "template (no local model reachable)", "text": self._template(recent, states)}

    def _template(self, events, states):
        detected = sorted({label_for(self.entries[e["node"]]) for e in events
                           if e["kind"] == "quarantine" and e["node"] in self.entries})
        adopted = sorted({label_for(self.entries[e["node"]]) for e in events
                          if e["kind"] == "vax_adopted" and e["node"] in self.entries})
        rejected = sorted({e["detail"].split(":")[0] for e in events if e["kind"] == "vax_rejected"})
        target = self.immunity["target"] or "the attacker"
        def names(xs):
            return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]

        parts = []
        if detected:
            many = len(detected) > 1
            parts.append(f"{names(detected)} {'each ' if many else ''}noticed traffic from {target} that did not "
                         f"match what {'they' if many else 'it'} had learned as normal, "
                         f"isolated {'themselves' if many else 'itself'} and broadcast a signed vaccine.")
        if adopted:
            parts.append(f"{names(adopted)} received matching vaccines from two independent devices "
                         f"and blocked {target} before it ever reached {'them' if len(adopted) > 1 else 'it'}.")
        if rejected:
            parts.append("Poisoned vaccines were thrown out: " + ", ".join(rejected) + ".")
        if not parts:
            parts.append("No incident yet: every device is running normally.")
        return " ".join(parts)

    # -- snapshot

    def snapshot(self):
        now = time.monotonic()
        with self.lock:
            nodes = []
            for nid in self.order:
                rec = self.nodes[nid]
                nodes.append({"id": nid, "label": label_for(self.entries[nid]),
                              "kind": self.entries[nid].get("kind", "python"), "ip": rec["ip"],
                              "online": self._online(nid, now), "status": rec["status"]})
            im = self.immunity
            return {
                "now": time.time(), "quorum": self.cfg["quorum"], "nodes": nodes,
                "bulb": {"online": now - self.bulb["seen"] < OFFLINE_AFTER, "status": self.bulb["status"]},
                "attacker": {"online": now - self.peers["attacker"]["seen"] < 5,
                             "ip": self.peers["attacker"]["ip"], "busy": self.peers["attacker"]["busy"]},
                "dumb": {"online": now - self.peers["dumb"]["seen"] < 5, "ip": self.peers["dumb"]["ip"]},
                "immunity": {"target": im["target"], "t0": im["t0"], "t1": im["t1"],
                             "nodes": {n: v[1] for n, v in im["nodes"].items()},
                             "instant": im["instant"]},
                "defenses": self.defenses, "hub_ip": self.hub_ip,
            }


def make_handler(dash):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path, _, query = self.path.partition("?")
            if path in ("/", "/index.html"):
                with open(INDEX, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if path == "/api/state":
                snap = dash.snapshot()
                if "log=1" in query:
                    with dash.lock:
                        snap["events"] = list(dash.events)[-80:]
                return self._send(200, snap)
            if path == "/events":
                return self._sse()
            self._send(404, {"error": "not found"})

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            parts = [p for p in self.path.partition("?")[0].split("/") if p]
            if parts[:2] == ["api", "scenario"]:
                ok, msg = dash.scenario(parts[2:])
            elif parts == ["api", "reset"]:
                ok, msg = dash.reset()
            elif parts == ["api", "relearn"]:
                ok, msg = dash.relearn()
            elif parts == ["api", "explain"]:
                return self._send(200, dash.explain())
            else:
                return self._send(404, {"error": "not found"})
            self._send(200 if ok else 409, {"ok": ok, "message": msg})

        def _sse(self):
            q = queue.Queue(maxsize=500)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            with dash.lock:
                backlog = list(dash.events)[-80:]
                dash.subscribers.append(q)
            try:
                self._emit("backlog", backlog)
                self._emit("state", dash.snapshot())
                last = time.monotonic()
                while True:
                    try:
                        kind, payload = q.get(timeout=0.25)
                        self._emit(kind, payload)
                    except queue.Empty:
                        pass
                    if time.monotonic() - last >= 0.25:
                        last = time.monotonic()
                        self._emit("state", dash.snapshot())
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            finally:
                with dash.lock:
                    if q in dash.subscribers:
                        dash.subscribers.remove(q)

        def _emit(self, kind, payload):
            self.wfile.write(f"event: {kind}\ndata: {json.dumps(payload)}\n\n".encode())
            self.wfile.flush()

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--http", default="127.0.0.1", help="HTTP bind address (0.0.0.0 to share on the LAN)")
    ap.add_argument("--port", type=int, help="HTTP port (default from config)")
    ap.add_argument("--no-hub", action="store_true", help="do not run the normal-traffic hub")
    args = ap.parse_args()
    cfg = hc.load_config(args.config)
    dash = Dashboard(cfg, run_hub=not args.no_hub)
    threading.Thread(target=dash.listen, name="udp", daemon=True).start()
    if dash.hub:
        dash.hub.start()
    port = args.port or cfg["network"]["http_port"]
    server = ThreadingHTTPServer((args.http, port), make_handler(dash))
    server.daemon_threads = True
    print(f"dashboard on http://{'localhost' if args.http in ('127.0.0.1', '0.0.0.0') else args.http}:{port}"
          f"  (status UDP {cfg['network']['status_port']}, hub {'on' if dash.hub else 'off'}, hub ip {dash.hub_ip})",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
