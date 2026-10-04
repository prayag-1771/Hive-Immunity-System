"""Simulated Bluetooth (BLE) bulb: it cannot run Hive, so only its hub can protect it.

Connects to the ESP32's Bluetooth hub and writes a short report every 2 s
("blebulb:<seq>:<light>"). When infected (dashboard button) it floods the hub with junk
writes; the ESP32 has learned its normal rate, cuts it off and refuses to let it back in
until an operator reset. Needs Linux with BlueZ and the bleak library (the Raspberry Pi):

  python3 -m venv ~/hive-venv && ~/hive-venv/bin/pip install bleak
  ~/hive-venv/bin/python tools/ble_bulb.py

Safety: it only ever talks to the hub (found by its own service UUID) and, over UDP, to
the dashboard on the local network.
"""

import argparse
import asyncio
import json
import os
import random
import select
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402
from scenarios import valid_trigger  # noqa: E402

SERVICE = "dfa90001-9f19-4d01-a7b2-6d341a4d5745"   # must match firmware/hive_node/ble_hub.h
REPORT = "dfa90002-9f19-4d01-a7b2-6d341a4d5745"
REPORT_EVERY_S = 2.0
FLOOD_PER_S = 30
REFUSED_WITHIN_S = 3.0   # a link the hub drops this fast means "blocked"


def report(name, seq, light):
    """The hub's report format, at most 20 bytes (fits the default BLE MTU)."""
    return f"{name}:{seq % 1_000_000}:{1 if light else 0}".encode()


def junk(rng, i):
    """What an infected bulb floods the hub with: never a valid report."""
    if i % 5 == 0:
        return b"blebulb:x:9"
    return bytes(rng.randrange(256) for _ in range(rng.randrange(12, 21)))


class Bulb:
    def __init__(self, cfg, name):
        self.cfg = cfg
        self.name = name
        self.infected = False
        self.state = "scanning"
        self.seq = 0
        self.light = False
        self.rng = random.Random()
        self.port = cfg["network"].get("ble_port", 47006)
        self.sock = net.udp_socket("0.0.0.0", self.port, broadcast=True)
        self.my_ip = net.guess_lan_ip()
        self.dash = hc.static_ip(cfg["dashboard"].get("ip"))
        self._logged = {}

    def log(self, text):
        print(f"{time.strftime('%H:%M:%S')} [blebulb] {text}", flush=True)

    def log_every(self, key, seconds, text):
        """Log a repeating condition at most once per `seconds`."""
        now = time.monotonic()
        if now - self._logged.get(key, -seconds) >= seconds:
            self._logged[key] = now
            self.log(text)

    # -- control channel (dashboard triggers), in a thread: plain sockets, no asyncio

    def control(self):
        last_seq, next_hello = -1, 0.0
        status_port = self.cfg["network"]["status_port"]
        while True:
            now = time.monotonic()
            if now >= next_hello:
                next_hello = now + 2.0
                hello = {"v": 1, "t": "hello", "role": "blebulb", "ip": self.my_ip,
                         "busy": self.infected, "ble": self.state}
                for ip in ([self.dash] if self.dash else net.broadcast_targets(self.cfg, self.my_ip)[:1]):
                    net.send(self.sock, hello, (ip, status_port))
            select.select([self.sock], [], [], 0.5)
            for data, ip in net.recv_all(self.sock):
                try:
                    m = json.loads(data)
                except ValueError:
                    continue
                if valid_trigger(m, self.cfg["admin_key"], ("infect", "heal")) and m["seq"] > last_seq:
                    last_seq = m["seq"]
                    self.dash = self.dash or ip
                    self.infected = m["name"] == "infect"
                    self.log("INFECTED: flooding the hub" if self.infected else "healed: normal reports")

    # -- Bluetooth side

    def drop_stale_links(self):
        """Release links BlueZ still holds to the hub (e.g. after this process was restarted).

        BlueZ keeps an LE link up after its client dies, and the hub doesn't advertise while
        it thinks the bulb is connected, so a fresh run would never see it.
        """
        try:
            out = subprocess.run(["bluetoothctl", "devices", "Connected"], capture_output=True,
                                 text=True, timeout=10).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "Device":
                    info = subprocess.run(["bluetoothctl", "info", parts[1]], capture_output=True,
                                          text=True, timeout=10).stdout
                    if SERVICE in info.lower():
                        subprocess.run(["bluetoothctl", "disconnect", parts[1]], capture_output=True, timeout=15)
                        self.log(f"released a stale link to the hub {parts[1]}")
        except (OSError, subprocess.SubprocessError):
            pass

    async def run(self):
        from bleak import BleakClient, BleakScanner
        from bleak.exc import BleakError

        self.drop_stale_links()
        unseen_since = time.monotonic()
        while True:
            self.state = "scanning" if self.state not in ("cut off", "refused") else self.state
            # LE-only discovery, so BlueZ never mistakes the hub for a classic Bluetooth device.
            device = await BleakScanner.find_device_by_filter(
                lambda d, ad: SERVICE in [u.lower() for u in ad.service_uuids], timeout=8.0,
                bluez={"filters": {"Transport": "le"}})
            if device is None:
                self.log_every("scan", 30, "hub not seen yet, still scanning")
                if time.monotonic() - unseen_since > 30:
                    self.drop_stale_links()
                    unseen_since = time.monotonic()
                continue
            unseen_since = time.monotonic()
            gone = asyncio.Event()
            client = BleakClient(device, disconnected_callback=lambda _c: gone.set(), timeout=15.0)
            started = time.monotonic()
            try:
                await client.connect()
                started = time.monotonic()
                self.state = "connected"
                self.log(f"connected to hub {device.address} ({device.name})")
                await self.talk(client, gone)
            except (BleakError, asyncio.TimeoutError, OSError) as e:
                if "br-connection" in str(e):
                    # BlueZ cached the hub as a classic device: forget it, rediscover over LE.
                    subprocess.run(["bluetoothctl", "remove", device.address], capture_output=True, timeout=10)
                    self.log(f"cleared a stale classic-Bluetooth entry for {device.address}")
                elif self.state != "connected":
                    self.log_every("connect", 10, f"could not connect to the hub: {type(e).__name__} {e}")
                elif not gone.is_set():
                    self.log(f"link error: {e}")
            finally:
                try:
                    await client.disconnect()
                except Exception:
                    pass
            lasted = time.monotonic() - started
            if self.state == "connected":
                if lasted < REFUSED_WITHIN_S:
                    self.state = "refused"
                    self.log("the hub refused the connection (blocked)")
                else:
                    self.state = "cut off"
                    self.log(f"the hub dropped the link after {lasted:.0f} s")
            await asyncio.sleep(2.0)

    async def talk(self, client, gone):
        next_report, next_toggle, i = 0.0, time.monotonic() + 5.0, 0
        while client.is_connected and not gone.is_set():
            now = time.monotonic()
            if self.infected:
                i += 1
                await client.write_gatt_char(REPORT, junk(self.rng, i), response=False)
                await asyncio.sleep(1.0 / FLOOD_PER_S)
                continue
            if now >= next_toggle:
                self.light = not self.light
                next_toggle = now + self.rng.uniform(4.0, 7.0)
            if now >= next_report:
                self.seq += 1
                await client.write_gatt_char(REPORT, report(self.name, self.seq, self.light), response=False)
                next_report = now + REPORT_EVERY_S
            await asyncio.sleep(0.1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    ap.add_argument("--name", default="blebulb", help="device name in its reports ([a-z0-9], max 10)")
    args = ap.parse_args()
    bulb = Bulb(hc.load_config(args.config), args.name)
    threading.Thread(target=bulb.control, name="control", daemon=True).start()
    bulb.log(f"Bluetooth bulb looking for the hub (service {SERVICE}); triggers on UDP {bulb.port}")
    try:
        asyncio.run(bulb.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
