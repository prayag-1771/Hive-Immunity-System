"""Attacker profile + incident report, built from what a source does to our decoy.

Pure functions (no sockets): given the list of interactions the decoy logged for one source,
describe the behaviour, match it against a tiny table of known patterns, and fill an incident
report a network owner could hand to their ISP or a CERT.

Safety: this only ever describes what an attacker did TO OUR OWN decoy. It flags a *source*
(IP/MAC), never a person, and the source may itself be a hacked victim device.
"""

import hashlib
import time

# A few heuristic signatures, clearly labelled. Each: (label, test over the lowercased command
# verbs seen). Order matters -- the first match wins.
KNOWN_PATTERNS = [
    ("default-credential sweep (Mirai-like)",
     lambda cmds: sum(c.startswith("login") for c in cmds) >= 2),
    ("command injection / remote-shell attempt",
     lambda cmds: any(any(t in c for t in (";", "$(", "wget", "curl", "busybox", "|sh", "| sh")) for c in cmds)),
    ("config / firmware exfiltration probe",
     lambda cmds: any("config" in c or "firmware" in c or "stream" in c for c in cmds)),
]


def _verbs(interactions):
    return [i.get("cmd", "").strip().lower() for i in interactions if i.get("cmd")]


def match_pattern(interactions):
    """(label, confidence 0-100). Honeytoken logic: any interaction with the decoy is already
    high-confidence hostile, so confidence starts high and rises with how much they revealed."""
    cmds = _verbs(interactions)
    label = "unknown pattern"
    for name, test in KNOWN_PATTERNS:
        try:
            if test(cmds):
                label = name
                break
        except Exception:
            pass
    base = 70 if cmds else 0
    confidence = min(99, base + 5 * len(set(cmds)) + (10 if label != "unknown pattern" else 0))
    return label, confidence


def fingerprint(interactions):
    """A short, stable signature of the ordered command verbs (to compare repeat offenders)."""
    joined = "|".join(_verbs(interactions))
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


def geo_hint(ip):
    """Offline hint only. We don't ship a GeoIP database, so we classify the address range and
    say where a production build would resolve it."""
    if ip.startswith(("10.", "192.168.", "127.")) or ip.startswith("172.16."):
        return "private/LAN address (same network as the decoy)"
    if ip.startswith("198.18."):
        return "benchmarking range (RFC 2544) — our own test traffic"
    return "public address — would resolve via a GeoIP/threat-intel feed in production"


def build_profile(src, interactions, mac=None):
    """A structured attacker profile from one source's decoy interactions."""
    ts = [i["ts"] for i in interactions if "ts" in i]
    first, last = (min(ts), max(ts)) if ts else (0.0, 0.0)
    cmds = [i.get("cmd", "") for i in interactions]
    label, confidence = match_pattern(interactions)
    distinct = sorted(set(_verbs(interactions)))
    return {
        "ip": src,
        "mac": mac,
        "geo_hint": geo_hint(src),
        "first_seen": first,
        "last_seen": last,
        "duration_s": round(last - first, 1),
        "interactions": len(interactions),
        "commands": cmds,
        "distinct_cmds": distinct,
        "fingerprint": fingerprint(interactions),
        "matched_pattern": label,
        "confidence": confidence,
        "summary": f"{len(interactions)} probes from {src}; pattern: {label}; confidence {confidence}%",
    }


def build_report(profile, org_name="Hive Demo Net", cert_contact="cert@example.org"):
    """A plain-text incident report, ready to file. Flags a source, not a person."""
    p = profile
    when = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "n/a"
    lines = [
        "HIVE IMMUNE SYSTEM — INCIDENT REPORT",
        "=" * 44,
        f"Reporting organisation : {org_name}",
        f"Suggested recipient    : {cert_contact}",
        f"Generated              : {when(time.time())}",
        "",
        "SOURCE (flagged, not accused — may itself be a compromised device)",
        f"  Address      : {p['ip']}" + (f"  MAC {p['mac']}" if p.get('mac') else ""),
        f"  Location     : {p['geo_hint']}",
        f"  First seen   : {when(p['first_seen'])}",
        f"  Last seen    : {when(p['last_seen'])}",
        f"  Engaged for  : {p['duration_s']} s on a decoy device (a fake, isolated service)",
        "",
        "BEHAVIOUR (everything the source sent to our decoy)",
    ]
    lines += [f"  {i + 1:>2}. {c}" for i, c in enumerate(p["commands"])] or ["  (none)"]
    lines += [
        "",
        "ASSESSMENT",
        f"  Pattern      : {p['matched_pattern']}",
        f"  Fingerprint  : {p['fingerprint']}",
        f"  Confidence   : {p['confidence']}%  (any contact with the decoy is hostile by design)",
        "",
        "RECOMMENDED ACTION",
        "  - Block this source at the gateway (Hive has already broadcast a vaccine for it).",
        "  - Report the address and timestamps to your ISP / CERT.",
        "  - If the source is on your own network, isolate and re-image that device.",
        "",
        "METHOD",
        "  Observe-only. The source was engaged on a decoy (honeypot/tarpit) that only replies",
        "  to connections it initiated to us. No traffic was ever sent toward the source's host.",
    ]
    return "\n".join(lines)
