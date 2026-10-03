"""Shared Hive logic: message limits, signing, features, detection, vaccine pipeline.

Everything in this module is pure: no sockets, and the current time is always passed in.
That keeps it unit-testable and lets the ESP32 firmware mirror it step for step.
"""

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re

PROTO_V = 1
MAX_MSG = 512          # any message larger than this is rejected before parsing
MAX_VAX = 300          # vaccines have a tighter limit
MAX_TTL = 600          # seconds; a vaccine can never ask for a longer block

FEATURE_NAMES = ("msgs_per_s", "distinct_senders", "unknown_ratio", "malformed_ratio", "mean_size")
N_FEATURES = len(FEATURE_NAMES)
STD_FLOOR = (1.0, 0.5, 0.05, 0.05, 5.0)

CMDS = ("ping", "light_on", "light_off", "status")
REASONS = ("flood", "unknown_sender", "malformed")
CTRL_CMDS = ("relearn", "reset")

NODE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,16}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

DEMO_DEFAULTS = {
    "learn_seconds": 20,
    "window_seconds": 1.0,
    "threshold": 6.0,
    "consecutive": 2,
    "quarantine_hold_s": 30,
    "vax_ttl_s": 300,
    "vax_rate_max_per_min": 3,
    "distrust_s": 300,
    "pending_s": 120,
}

NETWORK_DEFAULTS = {
    "data_port": 47000,
    "vax_port": 47001,
    "status_port": 47002,
    "sink_port": 47003,
    "attacker_port": 47004,
    "dumb_port": 47005,
    "http_port": 8080,
    "broadcast": "255.255.255.255",
}


# ---------------------------------------------------------------- config

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["network"] = {**NETWORK_DEFAULTS, **cfg.get("network", {})}
    cfg["demo"] = {**DEMO_DEFAULTS, **cfg.get("demo", {})}
    cfg.setdefault("quorum", 2)
    cfg.setdefault("hub", {"node_id": "hub", "ip": "auto"})
    cfg.setdefault("dashboard", {"ip": "auto"})
    cfg.setdefault("issuers", [])
    cfg.setdefault("protected", [])
    cfg["_path"] = os.path.abspath(path)
    return cfg


def issuer_keys(cfg):
    """Every identity that may sign a vaccine: the nodes plus extra issuers (gateway, ...)."""
    return {e["node_id"]: e["key"] for e in cfg["nodes"] + cfg["issuers"]}


def node_entry(cfg, node_id):
    for e in cfg["nodes"] + cfg["issuers"]:
        if e["node_id"] == node_id:
            return e
    raise KeyError(f"node '{node_id}' not in {cfg['_path']}")


def static_ip(value):
    """Config IPs may be 'auto' (discover at runtime); return the IP or None."""
    return value if value and value != "auto" else None


# ---------------------------------------------------------------- signing

def canonical(obj):
    """Bytes that get signed: the message without `sig`, sorted keys, no spaces."""
    body = {k: v for k, v in obj.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign(key_hex, obj):
    return hmac.new(bytes.fromhex(key_hex), canonical(obj), hashlib.sha256).hexdigest()


def verify(key_hex, obj):
    sig = obj.get("sig")
    return isinstance(sig, str) and hmac.compare_digest(sig, sign(key_hex, obj))


# ---------------------------------------------------------------- parsing / schema

def is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def is_ipv4(s):
    if not isinstance(s, str) or len(s) > 15:
        return False
    try:
        return str(ipaddress.IPv4Address(s)) == s
    except ValueError:
        return False


def parse(raw, limit=MAX_MSG):
    """Size check first, then JSON, then the common envelope. None means malformed."""
    if len(raw) > limit:
        return None
    try:
        msg = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(msg, dict) or msg.get("v") != PROTO_V or not isinstance(msg.get("t"), str):
        return None
    return msg


def valid_cmd(m):
    return (set(m) == {"v", "t", "src", "dst", "cmd", "seq"}
            and m["t"] == "cmd"
            and isinstance(m["src"], str) and NODE_ID_RE.match(m["src"]) is not None
            and isinstance(m["dst"], str) and (m["dst"] == "*" or NODE_ID_RE.match(m["dst"]) is not None)
            and m["cmd"] in CMDS
            and is_int(m["seq"]))


def valid_vax(m):
    return (set(m) == {"v", "t", "issuer", "seq", "rule", "target", "ttl", "reason", "sig"}
            and m["t"] == "vax"
            and isinstance(m["issuer"], str) and NODE_ID_RE.match(m["issuer"]) is not None
            and is_int(m["seq"]) and 0 <= m["seq"] < 2 ** 31
            and m["rule"] == "block"
            and is_ipv4(m["target"])
            and is_int(m["ttl"]) and 1 <= m["ttl"] <= MAX_TTL
            and m["reason"] in REASONS
            and isinstance(m["sig"], str) and HEX64_RE.match(m["sig"]) is not None)


def valid_ctrl(m):
    return (set(m) == {"v", "t", "cmd", "seq", "sig"}
            and m["t"] == "ctrl"
            and m["cmd"] in CTRL_CMDS
            and is_int(m["seq"]) and m["seq"] >= 0
            and isinstance(m["sig"], str) and HEX64_RE.match(m["sig"]) is not None)


def make_vax(issuer, key_hex, seq, target, ttl, reason):
    m = {"v": PROTO_V, "t": "vax", "issuer": issuer, "seq": seq, "rule": "block",
         "target": target, "ttl": ttl, "reason": reason}
    m["sig"] = sign(key_hex, m)
    return m


def make_ctrl(admin_key_hex, cmd, seq):
    m = {"v": PROTO_V, "t": "ctrl", "cmd": cmd, "seq": seq}
    m["sig"] = sign(admin_key_hex, m)
    return m


def encode(msg):
    return json.dumps(msg, separators=(",", ":")).encode()


# ---------------------------------------------------------------- features

class Window:
    """Counters for one detection window on the data port."""

    def __init__(self):
        self.count = 0
        self.by_sender = {}
        self.unknown = 0
        self.malformed = 0
        self.bytes = 0

    def add(self, ip, size, known, malformed):
        self.count += 1
        self.by_sender[ip] = self.by_sender.get(ip, 0) + 1
        self.bytes += size
        if not known:
            self.unknown += 1
        if malformed:
            self.malformed += 1

    def features(self, seconds):
        n = self.count
        return [
            n / max(seconds, 1e-3),
            float(len(self.by_sender)),
            self.unknown / n if n else 0.0,
            self.malformed / n if n else 0.0,
            self.bytes / n if n else 0.0,
        ]


class Baseline:
    """Per-feature running mean/std (Welford) plus the senders seen while learning."""

    def __init__(self):
        self.n = 0
        self.mean = [0.0] * N_FEATURES
        self.m2 = [0.0] * N_FEATURES
        self.known = set()

    def add(self, f):
        self.n += 1
        for i, x in enumerate(f):
            d = x - self.mean[i]
            self.mean[i] += d / self.n
            self.m2[i] += d * (x - self.mean[i])

    def std(self):
        out = []
        for i in range(N_FEATURES):
            s = math.sqrt(self.m2[i] / (self.n - 1)) if self.n > 1 else 0.0
            out.append(max(s, STD_FLOOR[i]))
        return out

    def z(self, f):
        sd = self.std()
        return [(f[i] - self.mean[i]) / sd[i] for i in range(N_FEATURES)]

    def to_dict(self):
        return {"n": self.n, "mean": self.mean, "m2": self.m2, "known": sorted(self.known)}

    @classmethod
    def from_dict(cls, d):
        b = cls()
        b.n, b.mean, b.m2, b.known = d["n"], list(d["mean"]), list(d["m2"]), set(d["known"])
        return b


class ZScoreDetector:
    name = "zscore"

    def __init__(self, threshold):
        self.threshold = threshold
        self.size_bytes = N_FEATURES * 2 * 4   # mean + std as float32

    def score(self, f, baseline):
        return max(abs(v) for v in baseline.z(f))


class AutoencoderDetector:
    """Tiny dense autoencoder (5 -> h -> 5) over baseline z-scores; weights from model.json."""

    name = "autoencoder"

    def __init__(self, model):
        self.w1, self.b1 = model["w1"], model["b1"]
        self.w2, self.b2 = model["w2"], model["b2"]
        self.clip = model.get("clip", 20.0)
        self.threshold = model["threshold"]
        self.size_bytes = 4 * (len(self.w1) * len(self.w1[0]) + len(self.b1)
                               + len(self.w2) * len(self.w2[0]) + len(self.b2))

    @classmethod
    def load(cls, path):
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def reconstruct(self, z):
        x = [max(-self.clip, min(self.clip, v)) for v in z]
        h = [math.tanh(sum(x[i] * self.w1[i][j] for i in range(len(x))) + self.b1[j])
             for j in range(len(self.b1))]
        return x, [sum(h[j] * self.w2[j][k] for j in range(len(h))) + self.b2[k]
                   for k in range(len(self.b2))]

    def score(self, f, baseline):
        x, y = self.reconstruct(baseline.z(f))
        return math.sqrt(sum((a - b) ** 2 for a, b in zip(x, y)) / len(x))


# ---------------------------------------------------------------- the node

class HiveNode:
    """One immune device. Feed it packets and ticks; read back events, vaccines, status."""

    def __init__(self, node_id, key_hex, keys, admin_key_hex, demo, quorum,
                 my_ip=None, hub_ip=None, protected=(), detector=None,
                 baseline=None, vax_seq=0, now=0.0, kind="python"):
        self.node_id = node_id
        self.key = key_hex
        self.keys = dict(keys)
        self.admin_key = admin_key_hex
        self.demo = {**DEMO_DEFAULTS, **demo}
        self.quorum = max(1, int(quorum))
        self.my_ip = my_ip
        self.hub_ip = hub_ip
        self.protected = set(protected)
        self.detector = detector or ZScoreDetector(self.demo["threshold"])
        self.kind = kind
        self.vax_seq = vax_seq

        self.baseline = baseline
        self.learn_start = None
        self.learn_base = None
        self.state = "healthy" if baseline else "learning"
        self.window = Window()
        self.window_start = now
        self.score = 0.0
        self.features = [0.0] * N_FEATURES
        self.hot = 0
        self.calm_since = None
        self.light = False

        self.blocklist = {}       # ip -> expiry time
        self.blocked_logged = set()
        self.pending = {}         # target -> {issuer: time}
        self.last_seq = {}        # issuer -> last accepted seq
        self.last_vax = {}        # issuer -> canonical bytes of last accepted vaccine
        self.vax_times = {}       # issuer -> recent accept times (rate limiting)
        self.distrusted = {}      # issuer -> until
        self.last_ctrl_seq = -1
        self._reset_counters()

        self.events = []
        self.outbox = []          # vaccines to broadcast
        self.dirty = False        # baseline or vax_seq changed: caller should persist

    # -- helpers

    def _reset_counters(self):
        self.blocked = 0
        self.dropped = 0
        self.vax_issued = 0
        self.vax_adopted = 0
        self.vax_rejected = 0

    def _event(self, kind, detail, now):
        self.events.append({"kind": kind, "detail": detail, "mono": now})

    def _trusted(self, ip):
        return ip == self.hub_ip or (self.baseline is not None and ip in self.baseline.known)

    def _protected(self, ip):
        return ip in (self.hub_ip, self.my_ip) or ip in self.protected

    def _block(self, ip, ttl, now):
        self.blocklist[ip] = max(self.blocklist.get(ip, 0.0), now + ttl)
        self.blocked_logged.discard(ip)
        self.pending.pop(ip, None)

    def is_blocked(self, ip, now):
        exp = self.blocklist.get(ip)
        return exp is not None and exp > now

    def drain(self):
        events, vax = self.events, self.outbox
        self.events, self.outbox = [], []
        return events, vax

    # -- data port

    def on_data(self, ip, raw, now):
        """Inbound pipeline. Returns the cmd name if a valid command was accepted."""
        if self.is_blocked(ip, now):
            self.blocked += 1
            if ip not in self.blocked_logged:
                self.blocked_logged.add(ip)
                self._event("blocked_first_packet", f"dropped first packet from {ip} (immune)", now)
            return None

        msg = parse(raw)
        if msg is not None and msg["t"] == "ctrl":
            self._on_ctrl(msg, now)
            return None

        if self.state == "quarantined" and not self._trusted(ip):
            self.dropped += 1
            return None

        ok = msg is not None and valid_cmd(msg)
        if ok and self.hub_ip is None and msg["src"] == "hub":
            self.hub_ip = ip
        if ok and ip == self.hub_ip and self.state == "learning" and self.learn_start is None:
            self.learn_start = now
            self.window = Window()
            self.window_start = now

        learning = self.state == "learning"
        known = learning or (self.baseline is not None and ip in self.baseline.known)
        self.window.add(ip, len(raw), known, not ok)
        if learning and self.learn_start is not None:
            if self.learn_base is None:
                self.learn_base = Baseline()
            self.learn_base.known.add(ip)

        if not ok:
            return None
        if msg["cmd"] == "light_on":
            self.light = True
        elif msg["cmd"] == "light_off":
            self.light = False
        return msg["cmd"]

    def _on_ctrl(self, msg, now):
        if not valid_ctrl(msg) or msg["seq"] <= self.last_ctrl_seq or not verify(self.admin_key, msg):
            self._event("ctrl_rejected", "unsigned or replayed control message", now)
            return
        self.last_ctrl_seq = msg["seq"]
        if msg["cmd"] == "reset":
            self.reset(now)
        else:
            self.relearn(now)

    def reset(self, now):
        self.blocklist.clear()
        self.blocked_logged.clear()
        self.pending.clear()
        self.distrusted.clear()
        self.vax_times.clear()
        self.hot = 0
        self.calm_since = None
        self._reset_counters()
        self.state = "healthy" if self.baseline else "learning"
        self.window = Window()
        self.window_start = now
        self._event("heal", "reset by operator", now)

    def relearn(self, now):
        self.baseline = None
        self.learn_base = None
        self.learn_start = now if self.hub_ip else None
        self.reset(now)
        self.state = "learning"
        self.dirty = True
        self._event("relearn", "learning normal traffic again", now)

    # -- vaccine port

    def on_vax(self, ip, raw, now):
        def reject(reason, detail):
            self.vax_rejected += 1
            self._event("vax_rejected", f"{reason}: {detail}", now)

        if len(raw) > MAX_VAX:
            return reject("garbage", f"{len(raw)} bytes from {ip}")
        m = parse(raw, MAX_VAX)
        if m is None or not valid_vax(m):
            return reject("garbage", f"bad format from {ip}")
        issuer = m["issuer"]
        if issuer == self.node_id:
            return  # our own broadcast looping back
        if issuer not in self.keys:
            return reject("unknown_issuer", issuer)
        if self.distrusted.get(issuer, 0.0) > now:
            return reject("distrusted", f"{issuer} is in autoimmune timeout")
        body = canonical(m)
        if self.last_vax.get(issuer) == body + m["sig"].encode():
            return  # same vaccine via broadcast and unicast: not an attack
        if m["seq"] <= self.last_seq.get(issuer, -1):
            return reject("replay", f"{issuer} seq {m['seq']}")
        if not verify(self.keys[issuer], m):
            return reject("forged", f"bad signature claiming {issuer}")
        self.last_seq[issuer] = m["seq"]
        self.last_vax[issuer] = body + m["sig"].encode()

        recent = [t for t in self.vax_times.get(issuer, []) if now - t < 60.0] + [now]
        self.vax_times[issuer] = recent
        if len(recent) > self.demo["vax_rate_max_per_min"]:
            self.distrusted[issuer] = now + self.demo["distrust_s"]
            for votes in self.pending.values():
                votes.pop(issuer, None)
            return reject("autoimmune", f"{issuer} sent {len(recent)} vaccines in 60 s, distrusted")

        target = m["target"]
        if self._protected(target):
            return reject("protected_target", f"{issuer} tried to block {target}")

        if self.is_blocked(target, now):
            self.blocklist[target] = max(self.blocklist[target], now + m["ttl"])
            self._event("vax_pending", f"{target} already blocked (confirmed by {issuer})", now)
            return
        votes = self.pending.setdefault(target, {})
        votes[issuer] = now
        if len(votes) >= self.quorum:
            who = ", ".join(sorted(votes))
            self._block(target, m["ttl"], now)
            self.vax_adopted += 1
            self._event("vax_adopted", f"immune to {target} (reports from {who})", now)
        else:
            self._event("vax_pending", f"{target} pending {len(votes)}/{self.quorum} (from {issuer})", now)

    # -- time

    def tick(self, now):
        for ip in [ip for ip, exp in self.blocklist.items() if exp <= now]:
            del self.blocklist[ip]
            self.blocked_logged.discard(ip)
            self._event("unblock", f"block on {ip} expired", now)
        horizon = now - self.demo["pending_s"]
        for target in list(self.pending):
            votes = {i: t for i, t in self.pending[target].items() if t > horizon}
            if votes:
                self.pending[target] = votes
            else:
                del self.pending[target]

        elapsed = now - self.window_start
        if elapsed < self.demo["window_seconds"]:
            return
        window, self.window, self.window_start = self.window, Window(), now
        self.features = window.features(elapsed)

        if self.state == "learning":
            self._learn(now)
            return
        self.score = self.detector.score(self.features, self.baseline)
        anomalous = self.score > self.detector.threshold
        self.hot = self.hot + 1 if anomalous else 0

        if anomalous and self.hot >= self.demo["consecutive"]:
            self._respond(window, now)
        if self.state == "quarantined":
            if anomalous:
                self.calm_since = None
            elif self.calm_since is None:
                self.calm_since = now
            elif now - self.calm_since >= self.demo["quarantine_hold_s"]:
                self.state = "healthy"
                self.calm_since = None
                self._event("heal", f"normal for {self.demo['quarantine_hold_s']} s, leaving quarantine", now)

    def _learn(self, now):
        if self.learn_start is None:
            return
        if self.learn_base is None:
            self.learn_base = Baseline()
        self.learn_base.add(self.features)
        if now - self.learn_start >= self.demo["learn_seconds"] and self.learn_base.n >= 3:
            self.baseline, self.learn_base = self.learn_base, None
            if self.hub_ip:
                self.baseline.known.add(self.hub_ip)
            self.state = "healthy"
            self.dirty = True
            self._event("learned", f"baseline from {self.baseline.n} windows, "
                                   f"{len(self.baseline.known)} known sender(s)", now)

    def learn_progress(self, now):
        if self.state != "learning" or self.learn_start is None:
            return 0.0 if self.state == "learning" else 1.0
        return min(1.0, (now - self.learn_start) / self.demo["learn_seconds"])

    def _culprit(self, window):
        ranked = sorted(window.by_sender.items(), key=lambda kv: -kv[1])
        candidates = [ip for ip, _ in ranked if not self._protected(ip)]
        unknown = [ip for ip in candidates if ip not in self.baseline.known]
        return (unknown or candidates or [None])[0]

    def _reason(self):
        z = [abs(v) for v in self.baseline.z(self.features)]
        if z[3] >= max(z) * 0.5 and self.features[3] > 0.2:
            return "malformed"
        if z[2] >= max(z) * 0.5 and self.features[2] > 0.2:
            return "unknown_sender"
        return "flood"

    def _respond(self, window, now):
        culprit = self._culprit(window)
        if culprit is not None and self.is_blocked(culprit, now):
            return
        if self.state != "quarantined":
            self.state = "quarantined"
            self.calm_since = None
            self._event("quarantine", f"score {self.score:.1f} > {self.detector.threshold:g}; "
                                      f"culprit {culprit or 'unknown'}", now)
        if culprit is None:
            return
        ttl = int(self.demo["vax_ttl_s"])
        self._block(culprit, ttl, now)
        self.vax_seq += 1
        self.dirty = True
        reason = self._reason()
        self.outbox.append(make_vax(self.node_id, self.key, self.vax_seq, culprit, ttl, reason))
        self.vax_issued += 1
        self._event("vax_issued", f"block {culprit} ({reason}), seq {self.vax_seq}", now)

    # -- reporting

    def status(self, now, ts):
        return {
            "v": PROTO_V, "t": "status", "node": self.node_id, "kind": self.kind,
            "state": self.state, "score": round(self.score, 2),
            "thr": self.detector.threshold, "det": self.detector.name,
            "model_bytes": self.detector.size_bytes,
            "features": [round(x, 2) for x in self.features],
            "blocked": self.blocked, "vax_issued": self.vax_issued,
            "vax_adopted": self.vax_adopted, "vax_rejected": self.vax_rejected,
            "blocklist": sorted(ip for ip, exp in self.blocklist.items() if exp > now)[:8],
            "pending": [[t, len(v)] for t, v in sorted(self.pending.items())][:8],
            "quorum": self.quorum, "light": self.light,
            "learn": round(self.learn_progress(now), 2), "ts": round(ts, 3),
        }
