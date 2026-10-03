"""Record the dashboard while it runs through the demo: a backup video for the pitch.

Opens the dashboard in a headless Edge/Chrome, captures frames over the DevTools
protocol, presses the demo buttons through the dashboard's API, adds a caption bar for
each step and writes an MP4. Run it on the dashboard laptop once everything is green.

  pip install websocket-client imageio imageio-ffmpeg pillow
  python tools/record_dashboard.py --out docs/demo-backup.mp4

A phone video of the real devices (the ESP32's LED!) is still the better backup; this is
the screen half of it.
"""

import argparse
import base64
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request

import imageio.v2 as imageio
import numpy as np
import websocket
from PIL import Image, ImageDraw, ImageFont

BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
]

STEPS = [  # (api path or None, seconds to hold, caption)
    (None, 4, "Hive: an immune system inside every tiny device. Everything is normal."),
    ("scenario/attack/esp32", 7, "Attack the ESP32: its 152-byte model spots the flood, it quarantines itself and sends a signed vaccine"),
    ("scenario/attack/lapB", 7, "Attack Laptop B: a second independent report, so Laptop A adopts the vaccine and is immune"),
    ("scenario/attack/lapA", 6, "Attack Laptop A: blocked on the very first packet, no quarantine needed"),
    ("scenario/infect_bulb", 7, "A Wi-Fi bulb that can't run Hive starts flooding: the gateway isolates it"),
    ("scenario/infect_ble", 8, "A Bluetooth bulb floods the ESP32's Bluetooth hub: cut off, reconnections refused"),
    ("scenario/cure", 15, "Attack the cure: forged, tampered, oversized, replayed and spammed vaccines are all rejected"),
    ("reset", 6, "Reset: everything heals, nothing restarted. Peer-to-peer, offline, no cloud."),
]


def api(base, path):
    req = urllib.request.Request(f"{base}/api/{path}", b"", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("ok", True)
    except Exception:
        return False


def find_browser(explicit):
    for path in ([explicit] if explicit else []) + BROWSERS:
        if path and os.path.exists(path):
            return path
    raise SystemExit("no Edge/Chrome/Chromium found; pass --browser")


class Recorder:
    def __init__(self, browser, url, width, height, port):
        self.profile = tempfile.mkdtemp(prefix="hive-rec-")
        self.proc = subprocess.Popen(
            [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
             f"--remote-debugging-port={port}", "--remote-allow-origins=*",
             f"--user-data-dir={self.profile}", f"--window-size={width},{height}",
             "--force-device-scale-factor=1", url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.frames = []          # (time, jpeg bytes)
        self.ws = websocket.create_connection(self._page_ws(port, url), timeout=30)
        self.next_id = 1
        self.running = True
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self._call("Page.startScreencast", {"format": "jpeg", "quality": 85, "maxWidth": width,
                                            "maxHeight": height, "everyNthFrame": 1})

    def _page_ws(self, port, url):
        end = time.time() + 20
        while time.time() < end:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as r:
                    for t in json.loads(r.read()):
                        if t.get("type") == "page" and t.get("url", "").startswith(url.split("?")[0]):
                            return t["webSocketDebuggerUrl"]
            except Exception:
                pass
            time.sleep(0.3)
        raise SystemExit("the browser did not open the dashboard")

    def _call(self, method, params=None):
        self.ws.send(json.dumps({"id": self.next_id, "method": method, "params": params or {}}))
        self.next_id += 1

    def _read(self):
        while self.running:
            try:
                msg = json.loads(self.ws.recv())
            except Exception:
                return
            if msg.get("method") == "Page.screencastFrame":
                p = msg["params"]
                self.frames.append((time.monotonic(), base64.b64decode(p["data"])))
                self._call("Page.screencastFrameAck", {"sessionId": p["sessionId"]})

    def stop(self):
        self.running = False
        try:
            self._call("Page.stopScreencast")
            self.ws.close()
        except Exception:
            pass
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


def caption_bar(text, width, font):
    bar = Image.new("RGB", (width, 56), (245, 158, 11))
    ImageDraw.Draw(bar).text((20, 13), text, fill=(10, 15, 30), font=font)
    return bar


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8080/")
    ap.add_argument("--out", default="demo-backup.mp4")
    ap.add_argument("--browser")
    ap.add_argument("--fps", type=int, default=12)
    ap.add_argument("--port", type=int, default=9333)
    args = ap.parse_args()
    base = args.url.split("?")[0].rstrip("/")

    api(base, "reset")
    time.sleep(3)
    rec = Recorder(find_browser(args.browser), args.url, 1600, 900, args.port)
    time.sleep(2)
    timeline = []                 # (start time, caption)
    for path, hold, text in STEPS:
        if path and not api(base, path):
            print(f"skipped {path} (not available)", flush=True)
            continue
        timeline.append((time.monotonic(), text))
        print(f"{text}", flush=True)
        time.sleep(hold)
    end = time.monotonic()
    rec.stop()
    if not rec.frames:
        raise SystemExit("no frames captured")

    try:
        font = ImageFont.truetype("segoeuib.ttf", 26)
    except OSError:
        font = ImageFont.load_default()
    width, height = 1280, 720
    writer = imageio.get_writer(args.out, fps=args.fps, codec="libx264", quality=7,
                                pixelformat="yuv420p", macro_block_size=8)
    t, fi, ci, frame = timeline[0][0], 0, 0, None
    while t <= end:
        while fi < len(rec.frames) and rec.frames[fi][0] <= t:
            frame = Image.open(io.BytesIO(rec.frames[fi][1])).convert("RGB").resize((width, height), Image.LANCZOS)
            fi += 1
        while ci + 1 < len(timeline) and timeline[ci + 1][0] <= t:
            ci += 1
        if frame is not None:
            canvas = Image.new("RGB", (width, height + 56))
            canvas.paste(caption_bar(timeline[ci][1], width, font), (0, 0))
            canvas.paste(frame, (0, 56))
            writer.append_data(np.asarray(canvas))
        t += 1.0 / args.fps
    writer.close()
    print(f"wrote {args.out}: {end - timeline[0][0]:.0f} s, {len(rec.frames)} captured frames, "
          f"{os.path.getsize(args.out) / 1e6:.1f} MB", flush=True)


if __name__ == "__main__":
    main()
