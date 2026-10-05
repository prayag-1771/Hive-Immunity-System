"""Small UDP helpers shared by the agent, hub, dashboard, gateway and scenario tools."""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(ROOT, "config", "nodes.json")


def udp_socket(bind_ip="0.0.0.0", port=0, broadcast=False, blocking=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if broadcast:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((bind_ip or "0.0.0.0", port))
    s.setblocking(blocking)
    return s


def guess_lan_ip(probe="10.255.255.255"):
    """The address our default route would use. No packet is sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((probe, 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def broadcast_targets(cfg, my_ip):
    """Where broadcasts go. 'auto' = this /24's directed broadcast plus 255.255.255.255.

    Sending both is safe: receivers silently drop an identical copy of a vaccine. The
    directed form matters on Windows, where 255.255.255.255 may leave on the wrong NIC.
    """
    b = cfg["network"].get("broadcast")
    if not b:
        return []
    if b != "auto":
        return [b]
    out = ["255.255.255.255"]
    if my_ip and not my_ip.startswith("127.") and my_ip != "0.0.0.0":
        out.insert(0, my_ip.rsplit(".", 1)[0] + ".255")
    return out


def peer_ips(cfg, exclude=()):
    """Static IPs of every vaccine-capable peer listed in the config."""
    out = []
    for e in cfg["nodes"]:
        ip = e.get("ip")
        if ip and ip != "auto" and ip not in exclude and ip not in out:
            out.append(ip)
    return out


def _parse_netsh(text):
    """SSIDs in `netsh wlan show interfaces` output (skips the BSSID lines)."""
    out = []
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "SSID" and value.strip():
            out.append(value.strip())
    return out


def _parse_iw(text):
    """SSIDs in `iw dev` output: one "ssid <name>" line per connected interface."""
    return [line.strip()[5:] for line in text.splitlines() if line.strip().startswith("ssid ")]


def _parse_nmcli(text):
    """SSIDs marked active in `nmcli -t -f active,ssid dev wifi` (":" is escaped as "\\:")."""
    out = []
    for line in text.splitlines():
        if line.startswith("yes:") and line[4:]:
            out.append(line[4:].replace("\\:", ":").replace("\\\\", "\\"))
    return out


def wifi_ssids():
    """Names of the Wi-Fi networks this machine is on: [] if none, None if it can't tell."""
    if os.name == "nt":
        tools = [(["netsh", "wlan", "show", "interfaces"], _parse_netsh)]
    else:
        tools = [(["iw", "dev"], _parse_iw), (["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], _parse_nmcli)]
    for cmd, parse in tools:
        if not shutil.which(cmd[0]):
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            return parse(r.stdout)
    return None


def fixed_ips(cfg):
    """The config's fixed addresses (dashboard and nodes), skipping "auto"."""
    ips = [(cfg.get("dashboard") or {}).get("ip")] + [n.get("ip") for n in cfg.get("nodes", [])]
    return [ip for ip in ips if ip and ip != "auto"]


def loopback_only(cfg):
    """True for the one-laptop simulation: every fixed address is a 127.0.0.x."""
    fixed = fixed_ips(cfg)
    return bool(fixed) and all(ip.startswith("127.") for ip in fixed)


def demo_network_problem(cfg, my_ip=None, ssids=False):
    """None when this machine is on the demo's own network, else the reason in one line.

    Ours means: sharing a /24 with an address fixed in the config, or joined to the hotspot
    the config names (esp32.ssid, the network the ESP32 is flashed for). When neither can be
    checked (no hotspot named, no Wi-Fi tools) the answer is None: nothing to compare with.
    """
    if loopback_only(cfg):
        return None   # the simulation never leaves this machine, so it runs on any network
    my_ip = my_ip or guess_lan_ip()
    if any(ip.rsplit(".", 1)[0] == my_ip.rsplit(".", 1)[0] for ip in fixed_ips(cfg)):
        return None
    want = ((cfg.get("esp32") or {}).get("ssid") or "").strip()
    if not want:
        return None
    if ssids is False:
        ssids = wifi_ssids()
    # Compare trimmed names: tools differ in how they show stray spaces around an SSID.
    if ssids is None or want in [s.strip() for s in ssids]:
        return None
    where = "Wi-Fi " + ", ".join(f"'{s}'" for s in ssids) if ssids else "no Wi-Fi network"
    return f"this machine is on {where} ({my_ip}), not the demo hotspot '{want}'"


_demo = {"cfg": None, "ok": True, "at": -1e9}


def set_demo_network(cfg):
    """Register the config whose network is ours: limited broadcasts only go out there."""
    _demo.update(cfg=cfg, at=-1e9)


def on_demo_network(max_age=5.0):
    """Cached answer to "is this machine on the demo network?" (True if none registered)."""
    if _demo["cfg"] is None:
        return True
    now = time.monotonic()
    if now - _demo["at"] >= max_age:
        _demo.update(ok=demo_network_problem(_demo["cfg"]) is None, at=now)
    return _demo["ok"]


_route_cache = {}
_warned = {}


def on_local_segment(ip):
    """True for loopback, broadcast and addresses on this machine's own network segment.

    Hive only ever talks to devices on its own private network. If a machine changes
    networks (say the demo hotspot drops and the laptop rejoins a campus Wi-Fi), traffic
    for the old addresses must not leave through the new network's router. The OS routing
    table decides: connect() on a UDP socket (which sends nothing) reveals the local
    address that would be used, and the destination must share its /24. And nothing
    leaves the machine at all while it is known to be on another network than the demo's
    (see set_demo_network), not even to that network's own addresses or broadcast.
    """
    if ip.startswith("127."):
        return True
    if not on_demo_network():
        return False
    if ip == "255.255.255.255":
        # The simulation has no use for it: there it would only leak onto the real network.
        return not (_demo["cfg"] and loopback_only(_demo["cfg"]))
    now = time.monotonic()
    hit = _route_cache.get(ip)
    if hit and now - hit[1] < 3.0:
        return hit[0]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.connect((ip, 9))
        ok = s.getsockname()[0].rsplit(".", 1)[0] == ip.rsplit(".", 1)[0]
    except OSError:
        ok = False
    finally:
        s.close()
    _route_cache[ip] = (ok, now)
    return ok


def send(sock, msg, addr):
    if not on_local_segment(addr[0]):
        now = time.monotonic()
        if now - _warned.get(addr[0], -60.0) >= 60.0:
            _warned[addr[0]] = now
            why = ("this machine is not on the demo network" if addr[0] == "255.255.255.255"
                   else "it is outside this machine's local network")
            print(f"hive: not sending to {addr[0]}: {why}", file=sys.stderr, flush=True)
        return
    data = msg if isinstance(msg, bytes) else json.dumps(msg, separators=(",", ":")).encode()
    try:
        sock.sendto(data, addr)
    except OSError:
        pass  # unreachable peers must never take the sender down


def recv_all(sock, bufsize=65536):
    """Drain a non-blocking socket. Yields (data, ip).

    The buffer fits any UDP datagram, so oversized packets arrive whole and are rejected
    by the size checks (a smaller buffer raises WinError 10040 on Windows).
    """
    while True:
        try:
            data, addr = sock.recvfrom(bufsize)
        except (BlockingIOError, InterruptedError):
            return
        except ConnectionResetError:
            # Windows reports an ICMP "port unreachable" for an earlier sendto() here.
            continue
        yield data, addr[0]
