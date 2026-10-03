"""Small UDP helpers shared by the agent, hub, dashboard, gateway and scenario tools."""

import json
import os
import socket
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


_route_cache = {}
_warned = {}


def on_local_segment(ip):
    """True for loopback, broadcast and addresses on this machine's own network segment.

    Hive only ever talks to devices on its own private network. If a machine changes
    networks (say the demo hotspot drops and the laptop rejoins a campus Wi-Fi), traffic
    for the old addresses must not leave through the new network's router. The OS routing
    table decides: connect() on a UDP socket (which sends nothing) reveals the local
    address that would be used, and the destination must share its /24.
    """
    if ip.startswith("127.") or ip == "255.255.255.255":
        return True
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
            print(f"hive: not sending to {addr[0]}: it is outside this machine's local network",
                  file=sys.stderr, flush=True)
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
