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
sys.path.insert(0, os.path.join(ROOT, "gateway"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402
import epidemic  # noqa: E402  (same directory as this file)
from decoy import Decoy  # noqa: E402  (gateway/)
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
        # The decoy/tarpit (gateway/decoy.py). Runs here so the one-laptop demo works too.
        self.decoy = Decoy(cfg, net)
        self.order = [e["node_id"] for e in cfg["nodes"]]
        self.entries = {e["node_id"]: e for e in cfg["nodes"]}
        self.nodes = {nid: {"status": None, "ip": hc.static_ip(e.get("ip")), "seen": 0.0}
                      for nid, e in self.entries.items()}
        self.gateway_ip = next((hc.static_ip(e.get("ip")) for e in cfg["issuers"]
                                if e["node_id"] == "gateway"), None)
        self.devices = {}   # devices that cannot run Hive: Wi-Fi ("dumb", via the gateway), BLE (via the hub)
        self.peers = {
            "attacker": {"ip": hc.static_ip(cfg["attacker"].get("ip")), "seen": 0.0, "busy": False},
            "dumb": {"ip": hc.static_ip(cfg["dumb"].get("ip")), "seen": 0.0, "busy": False},
            "blebulb": {"ip": None, "seen": 0.0, "busy": False, "ble": None},
        }
        self.events = collections.deque(maxlen=200)
        self.subscribers = []
        self.defenses = {}
        self.trigger_seq = int(time.time() * 1000)
        # Every event is stamped with the dashboard's own clock on arrival: devices' clocks
        # can disagree (an offline Pi has no battery-backed clock, the ESP32 has none).
        self.clock = time.time
        self.last_event_key, self.last_event_at = None, 0.0
        self.network = None   # why this machine is not on the demo network, None while it is
        # Latest detect/spread times for the Epidemic Meter. Before any live run, the figures
        # measured on our real hardware, so the "Project to 10,000" button always has numbers.
        self.last_timing = {"t_detect": 1.6, "t_spread": 0.2, "live": False}
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
            self._record_timing(im)

    def _record_timing(self, im):
        """Keep the latest live detect/spread times for the Epidemic Meter (both on the
        dashboard clock).

        t_detect = first attack packet -> the first device quarantining itself.
        t_spread = the second device's report (quorum reached) -> the last device immune.

        Spread is measured from the *second* report on purpose: the gap before it is the
        operator pressing the next attack button, not the system's speed (the same reason
        the time-to-immunity figure overcounts). From quorum onward, it is all Hive.
        """
        tss = sorted(ts for ts, _ in im["nodes"].values())
        quorum_ts = tss[1] if len(tss) > 1 else tss[0]
        self.last_timing = {"t_detect": round(max(0.0, tss[0] - im["t0"]), 2),
                            "t_spread": round(max(0.0, im["t1"] - quorum_ts), 2), "live": True}

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
                elif msg.get("kind") in ("dumb", "ble") and isinstance(node, str):
                    self.devices[node] = {"status": msg, "seen": now}
                    if msg["kind"] == "dumb":
                        self.gateway_ip = self.gateway_ip or ip
            elif t == "hello" and msg.get("role") in self.peers:
                self.peers[msg["role"]].update(ip=ip, seen=now, busy=bool(msg.get("busy")))
                if msg["role"] == "blebulb":
                    self.peers["blebulb"]["ble"] = msg.get("ble")
            elif t == "event" and isinstance(msg.get("kind"), str):
                key = (msg.get("node"), msg["kind"], msg.get("detail"))
                if key == self.last_event_key and self.clock() - self.last_event_at < 0.3:
                    return  # the same event delivered twice (e.g. two broadcast forms)
                self.last_event_key, self.last_event_at = key, self.clock()
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
        port = self.cfg["network"][{"attacker": "attacker_port", "dumb": "dumb_port", "blebulb": "ble_port"}[role]]
        if not peer["ip"]:
            tool = {"attacker": "scenarios.py serve", "dumb": "dumb_device.py", "blebulb": "ble_bulb.py"}[role]
            return False, f"{role} is not connected (start tools/{tool})"
        self.trigger_seq = max(self.trigger_seq + 1, int(time.time() * 1000))
        m = {"v": 1, "t": "trigger", "name": name, "seq": self.trigger_seq, "args": args}
        m["sig"] = hc.sign(self.cfg["admin_key"], m)
        addr = (peer["ip"], port)
        net.send(self.sock, m, addr)
        # A second copy a moment later in case Wi-Fi drops the first: receivers silently
        # ignore a sequence number they have already acted on.
        threading.Timer(0.15, net.send, args=(self.sock, m, addr)).start()
        return True, f"{name} sent to {role}"

    def _ctrl(self, cmd, only=None):
        """Send a signed control command to every node (or the node ids in `only`) and the gateway."""
        self.trigger_seq = max(self.trigger_seq + 1, int(time.time() * 1000))
        raw = hc.encode(hc.make_ctrl(self.cfg["admin_key"], cmd, self.trigger_seq))
        port = self.cfg["network"]
        ips = {rec["ip"] for nid, rec in self.nodes.items() if rec["ip"] and (only is None or nid in only)}
        for ip in ips:
            net.send(self.sock, raw, (ip, port["data_port"]))
        if self.gateway_ip and only is None:
            net.send(self.sock, raw, (self.gateway_ip, port["sink_port"]))
        return len(ips)

    def _confirm_reset(self, since, tries=2, wait=1.5):
        """Every node reports "heal" when it resets. UDP can drop the one reset packet (most
        likely for the ESP32, whose radio is busy with Bluetooth), which would leave a
        Bluetooth device blocked: send a fresh reset to online nodes that stay silent."""
        for _ in range(tries):
            time.sleep(wait)
            now = time.monotonic()
            with self.lock:
                healed = {e["node"] for e in self.events if e["kind"] == "heal" and e["ts"] >= since}
                silent = [n for n in self.order if self.nodes[n]["ip"] and self._online(n, now) and n not in healed]
            if not silent:
                return
            self._ctrl("reset", only=silent)

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
        if name in ("infect_ble", "heal_ble"):
            ok, msg = self._trigger("blebulb", "infect" if name == "infect_ble" else "heal")
            if ok and name == "infect_ble":
                self.note("pressed: infect the Bluetooth bulb", "scenario")
            return ok, msg
        if name == "explore_decoy":
            # The flagged attacker probes our decoy (a fake isolated device). Observe-only.
            port = self.cfg["network"].get("decoy_port", 48080)
            ok, msg = self._trigger("attacker", "explore", decoy_ip=self.my_ip, decoy_port=port)
            if ok:
                self.note("pressed: send the attacker into the decoy", "scenario")
            return ok, msg
        return False, f"unknown scenario {'/'.join(parts)}"

    def reset(self):
        since = self.clock()
        n = self._ctrl("reset")
        threading.Thread(target=self._confirm_reset, args=(since,), name="confirm-reset", daemon=True).start()
        if self.peers["attacker"]["ip"]:
            self._trigger("attacker", "stop")
        if self.peers["dumb"]["ip"]:
            self._trigger("dumb", "heal")
        if self.peers["blebulb"]["ip"]:
            self._trigger("blebulb", "heal")
        with self.lock:
            self._reset_immunity()
            self.defenses = {}
        self.decoy.reset()
        self.note(f"reset: everyone back to healthy ({n} node(s))", "reset")
        return True, "reset sent"

    def relearn(self):
        n = self._ctrl("relearn")
        self.note(f"relearn: {n} node(s) learning normal traffic again", "reset")
        return True, "relearn sent"

    # -- explain (optional local open model)

    def _ollama(self, payload, timeout):
        ex = self.cfg.get("explain", {})
        url = ex.get("url", "http://127.0.0.1:11434") + "/api/generate"
        # keep_alive -1: stay loaded for the whole demo. think False: Gemma 4 would otherwise spend
        # its token budget on hidden reasoning and return an empty answer.
        body = json.dumps({"model": ex.get("model", "gemma4:e2b-it-qat"), "stream": False,
                           "keep_alive": -1, "think": False, **payload}).encode()
        req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())

    def warm_model(self):
        """Load the model once at start-up, so a judge's first click doesn't wait for it.

        The first load on a machine can take minutes (CUDA compiles its kernels), so this waits
        generously; a client that gives up would make Ollama abort the load.
        """
        try:
            self._ollama({}, timeout=1200)
            print("explain: local model loaded", flush=True)
        except Exception:
            print("explain: no local model reachable; Explain incident will use the template", flush=True)

    def _model_loaded(self):
        ex = self.cfg.get("explain", {})
        try:
            with urllib.request.urlopen(ex.get("url", "http://127.0.0.1:11434") + "/api/ps", timeout=2) as r:
                loaded = {m.get("name") for m in json.loads(r.read()).get("models", [])}
            return ex.get("model", "gemma4:e2b-it-qat") in loaded
        except Exception:
            return False

    @staticmethod
    def _condense(events, keep=45):
        """Merge repeats (the same event from several nodes) so floods don't crowd out the attack."""
        lines = []
        for e in events:
            text = f"{e['kind'].replace('_', ' ')}: {e['detail']}"
            if lines and lines[-1][1] == text:
                if e["node"] not in lines[-1][0]:
                    lines[-1][0].append(e["node"])
                lines[-1][2] += 1
            else:
                lines.append([[e["node"]], text, 1])
        out = [f"- {', '.join(nodes)}: {text}" + (f" (x{n})" if n > len(nodes) else "") for nodes, text, n in lines]
        return out[-keep:]

    def explain(self):
        with self.lock:
            everything = list(self.events)
            states = {n: (self.nodes[n]["status"] or {}).get("state", "offline") for n in self.order}
        recent = everything[-150:]
        if not self._model_loaded():
            return {"source": "template (Gemma 4 is still loading or not running)",
                    "text": self._template(everything, states)}
        log = "\n".join(self._condense(recent))
        prompt = (
            "You narrate a live security demo for judges who are not security experts. The system: small "
            "devices each learn their normal network traffic, quarantine themselves when attacked, and send "
            "each other signed 'vaccines' that say 'block this sender', so the others become immune before the "
            "attacker reaches them. A router guards Wi-Fi devices that cannot run the software, and the ESP32 "
            "also acts as a Bluetooth hub that cuts off misbehaving Bluetooth devices. Fake vaccines are "
            "rejected.\n\nFrom the event log below, explain in at most 4 short, plain sentences what happened: "
            "what attacked, which devices detected it, how the others became immune, and anything rejected or "
            "cut off. No lists, no markdown.\n\nEvent log (oldest first):\n" + (log or "- nothing yet"))
        ex = self.cfg.get("explain", {})
        try:
            text = self._ollama({"prompt": prompt, "options": {"num_predict": 220, "temperature": 0.3}},
                                timeout=ex.get("timeout_s", 90)).get("response", "").strip()
            if text:
                return {"source": f"{ex.get('model', 'gemma4:e2b-it-qat')} (local, offline)", "text": text}
        except Exception:
            pass
        return {"source": "template (no local model reachable)", "text": self._template(everything, states)}

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
        if any(e["kind"] == "quarantine" and e["node"] == "gateway" for e in events):
            parts.append("The router noticed a Wi-Fi bulb that cannot run Hive suddenly flooding the network "
                         "and isolated it.")
        if any(e["kind"] == "ble_quarantine" for e in events):
            parts.append("The ESP32's Bluetooth hub cut off a Bluetooth bulb that started flooding it with "
                         "junk, and refuses to let it reconnect.")
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
                "devices": [{"id": d, "kind": rec["status"].get("kind"), "online": now - rec["seen"] < OFFLINE_AFTER,
                             "status": rec["status"]}
                            for d, rec in sorted(self.devices.items(),
                                                 key=lambda kv: (kv[1]["status"].get("kind") != "dumb", kv[0]))],
                "attacker": {"online": now - self.peers["attacker"]["seen"] < 5,
                             "ip": self.peers["attacker"]["ip"], "busy": self.peers["attacker"]["busy"]},
                "dumb": {"online": now - self.peers["dumb"]["seen"] < 5, "ip": self.peers["dumb"]["ip"]},
                "blebulb": {"online": now - self.peers["blebulb"]["seen"] < 5, "ip": self.peers["blebulb"]["ip"],
                            "busy": self.peers["blebulb"]["busy"], "ble": self.peers["blebulb"]["ble"]},
                "immunity": {"target": im["target"], "t0": im["t0"], "t1": im["t1"],
                             "nodes": {n: v[1] for n, v in im["nodes"].items()},
                             "times": {n: round(v[0] - im["t0"], 2) for n, v in im["nodes"].items()} if im["t0"] else {},
                             "instant": im["instant"]},
                "defenses": self.defenses, "hub_ip": self.hub_ip, "network": self.network,
                "decoy": self.decoy.snapshot(),
            }

    def epidemic_projection(self):
        """Project the latest measured detect/spread speed onto a city of 10,000 devices."""
        with self.lock:
            timing = dict(self.last_timing)
        proj = epidemic.project(timing, self.cfg.get("epidemic", hc.EPIDEMIC_DEFAULTS))
        proj["timing"] = timing
        proj["timing_source"] = "measured live this run" if timing.get("live") else \
            "measured on our real hardware (no live run yet this session)"
        return proj

    def watch_network(self):
        """Keep `network` current, so the page says so when this laptop leaves the hotspot
        (Windows may hop to a known network with internet when the hotspot has none)."""
        while True:
            self.network = net.demo_network_problem(self.cfg)
            time.sleep(5)


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
            if path == "/api/epidemic":
                return self._send(200, dash.epidemic_projection())
            if path == "/api/attacker":
                return self._send(200, {"profiles": dash.decoy.get_profiles()})
            if path == "/api/report":
                src = dict(p.split("=", 1) for p in query.split("&") if "=" in p).get("src")
                if not src:
                    return self._send(400, {"error": "need ?src=IP"})
                return self._send(200, dash.decoy.get_report(src))
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


class QuietHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # A browser that drops its connection (page closed, network change) is routine:
        # keep the console readable for the presenter instead of printing a traceback.
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--http", default="127.0.0.1", help="HTTP bind address (0.0.0.0 to share on the LAN)")
    ap.add_argument("--port", type=int, help="HTTP port (default from config)")
    ap.add_argument("--no-hub", action="store_true", help="do not run the normal-traffic hub")
    args = ap.parse_args()
    cfg = hc.load_config(args.config)
    net.set_demo_network(cfg)
    dash = Dashboard(cfg, run_hub=not args.no_hub)
    threading.Thread(target=dash.listen, name="udp", daemon=True).start()
    dash.decoy.start()
    if dash.hub:
        dash.hub.start()
    threading.Thread(target=dash.warm_model, name="warm-model", daemon=True).start()
    threading.Thread(target=dash.watch_network, name="network", daemon=True).start()
    port = args.port or cfg["network"]["http_port"]
    server = QuietHTTPServer((args.http, port), make_handler(dash))
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
