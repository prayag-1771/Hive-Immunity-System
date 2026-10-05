"""Decoy / tarpit: a fake, isolated "smart camera" that flagged attackers are routed into.

A honeypot. Nothing legitimate ever talks to it, so ANY interaction is a high-confidence
attacker signal (the honeytoken principle). It answers slowly, to hold the attacker's time
(a tarpit), logs everything they try, and hands the log to profiler.py to build an attacker
profile and an incident report.

SAFETY — observe-only intelligence gathering on OUR OWN decoy:
  - It only ever replies to a source that connected to it; it never initiates traffic, never
    scans, probes, or connects back. No packet leaves toward the attacker's host except the
    slow fake reply to their own message.
  - It is a lookup table, not a shell: it never runs anything the attacker sends, only logs it
    and returns a canned fake response.
  - In the demo the "attacker" is our own tools/scenarios.py on our own hotspot.
"""

import json
import os
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Canned fake "smart camera" responses. Pure lookup — nothing is executed.
CANNED = {
    "login": "OK  CamOS 2.1 — welcome, admin",
    "get /config": '{"model":"CamOS-2.1","rtsp":"554","admin":"admin","wifi":"REDACTED"}',
    "get /stream": "rtsp://10.0.0.9:554/live  (fake stream handle 0x8a21)",
    "get /firmware": "firmware v2.1.0-build417 — use SET /firmware to update",
    "set": "OK  queued (reboot required)",
    "reboot": "OK  rebooting in 3s...",
    "help": "commands: LOGIN <u>:<p> | GET /config|/stream|/firmware | SET | REBOOT",
}


def parse_cmd(raw):
    """Turn a raw line into a short normalised label for the profiler. Never executed."""
    text = raw.decode("utf-8", "replace").strip()
    low = text.lower()
    if low.startswith("login"):
        return "login " + text[5:].strip()[:24]
    for key in ("get /config", "get /stream", "get /firmware", "reboot", "set", "help"):
        if low.startswith(key):
            return key if key != "set" else "set " + text[3:].strip()[:24]
    return (low[:28] or "(empty)")


def canned_reply(cmd):
    for key, resp in CANNED.items():
        if cmd.startswith(key):
            return resp
    return "ERR  unknown command"


class Decoy:
    def __init__(self, cfg, net_mod):
        self.cfg = cfg
        self.net = net_mod
        d = cfg.get("decoy", {})
        self.enabled = d.get("enabled", True)
        self.delay = float(d.get("reply_delay_s", 1.5))
        self.max_lines = int(d.get("max_log_lines", 2000))
        self.port = cfg["network"].get("decoy_port", 48080)
        self.org = cfg.get("report", {}).get("org_name", "Hive Demo Net")
        self.cert = cfg.get("report", {}).get("cert_contact", "cert@example.org")
        self.lock = threading.Lock()
        self.by_src = {}          # src ip -> list of {ts, raw, cmd}
        self.order = []           # srcs in first-seen order
        self.active = None        # most recent src
        self.log_path = os.path.join(ROOT, "data", "attacker_log.jsonl")
        self.sock = None

    # -- the fake service

    def start(self):
        if not self.enabled:
            return
        self.sock = self.net.udp_socket("0.0.0.0", self.port, broadcast=True)
        threading.Thread(target=self._serve, name="decoy", daemon=True).start()

    def _serve(self):
        import select
        while True:
            select.select([self.sock], [], [], 0.5)
            while True:
                try:
                    data, addr = self.sock.recvfrom(4096)   # full (host, port): reply to the exact sender
                except (BlockingIOError, InterruptedError):
                    break
                except (ConnectionResetError, OSError):
                    continue
                self._log(addr[0], data)
                # Reply slowly, only to the source that contacted us (tarpit). Never initiated.
                threading.Timer(self.delay, self._reply, args=(addr, parse_cmd(data))).start()

    def _reply(self, addr, cmd):
        try:
            self.net.send(self.sock, ("HIVE-CAM> " + canned_reply(cmd)).encode(), addr)
        except Exception:
            pass

    def _log(self, src, raw):
        now = time.time()
        rec = {"ts": now, "src": src, "raw": raw.decode("utf-8", "replace")[:120], "cmd": parse_cmd(raw)}
        with self.lock:
            if src not in self.by_src:
                self.by_src[src] = []
                self.order.append(src)
            self.by_src[src].append({"ts": now, "raw": rec["raw"], "cmd": rec["cmd"]})
            if len(self.by_src[src]) > self.max_lines:
                self.by_src[src] = self.by_src[src][-self.max_lines:]
            self.active = src
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError:
            pass

    # -- feed for the profiler / dashboard

    def _profile(self, src):
        import profiler
        with self.lock:
            inter = list(self.by_src.get(src, []))
        return profiler.build_profile(src, inter)

    def get_profiles(self):
        with self.lock:
            srcs = list(self.order)
        return [self._profile(s) for s in srcs]

    def get_report(self, src):
        import profiler
        p = self._profile(src)
        return {"src": src, "json": p,
                "text": profiler.build_report(p, self.org, self.cert)}

    def snapshot(self):
        """Light view for the dashboard panel, or None when the decoy has seen nothing."""
        with self.lock:
            src = self.active
            if not src:
                return None
            inter = list(self.by_src.get(src, []))
        p = self._profile(src)
        return {
            "active": src,
            "first_seen": p["first_seen"],
            "last_seen": p["last_seen"],
            "interactions": len(inter),
            "commands": [i["cmd"] for i in inter][-10:],
            "pattern": p["matched_pattern"],
            "confidence": p["confidence"],
            "fingerprint": p["fingerprint"],
            "geo_hint": p["geo_hint"],
            "sources": len(self.order),
        }

    def reset(self):
        with self.lock:
            self.by_src.clear()
            self.order.clear()
            self.active = None
