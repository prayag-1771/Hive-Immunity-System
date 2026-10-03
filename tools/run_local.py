"""Run the whole demo on one laptop: dashboard + hub, every node, gateway guardian,
dumb bulb and attacker, each on its own 127.0.0.x address.

  python tools/run_local.py            # then open http://localhost:8080
  python tools/run_local.py --fresh    # forget saved baselines and learn again
  python tools/run_local.py --skip esp32   # leave a node out (e.g. the real ESP32 joins instead)

Ctrl+C stops everything.
"""

import argparse
import os
import signal
import shutil
import subprocess
import sys
import threading
import time
import webbrowser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
import hive_core as hc  # noqa: E402

LOCAL = os.path.join(ROOT, "config", "local.json")


def pump(name, proc, width):
    for line in iter(proc.stdout.readline, b""):
        sys.stdout.write(f"{name:<{width}} | {line.decode(errors='replace').rstrip()}\n")
        sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fresh", action="store_true", help="delete saved local baselines first")
    ap.add_argument("--skip", action="append", default=[], help="node_id to leave out (repeatable)")
    ap.add_argument("--detector", default="auto", choices=("auto", "zscore", "autoencoder"))
    ap.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    ap.add_argument("--http", default="127.0.0.1")
    args = ap.parse_args()

    if not os.path.exists(LOCAL):
        subprocess.check_call([sys.executable, os.path.join(ROOT, "tools", "provision_keys.py")])
    cfg = hc.load_config(LOCAL)
    if args.fresh:
        shutil.rmtree(os.path.join(ROOT, "data", "state", "local"), ignore_errors=True)

    py = [sys.executable, "-u"]
    procs = [("dashboard", py + ["dashboard/server.py", "--config", LOCAL, "--http", args.http])]
    for e in cfg["nodes"]:
        if e["node_id"] not in args.skip:
            procs.append((e["node_id"], py + ["agent/hive_agent.py", "--node", e["node_id"], "--config", LOCAL,
                                              "--detector", args.detector]))
    optional = [
        ("gateway", "gateway/guardian.py", []),
        ("bulb", "tools/dumb_device.py", []),
        ("attacker", "tools/scenarios.py", ["serve"]),
    ]
    for name, script, extra in optional:
        if os.path.exists(os.path.join(ROOT, script)):
            procs.append((name, py + [script] + extra + ["--config", LOCAL]))

    width = max(len(n) for n, _ in procs)
    running = []
    for name, cmd in procs:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        running.append((name, p))
        threading.Thread(target=pump, args=(name, p, width), daemon=True).start()
    port = cfg["network"]["http_port"]
    print(f"\n  Hive local demo: http://localhost:{port}   (Ctrl+C to stop)\n", flush=True)
    if args.open:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://localhost:{port}")).start()
    # SIGTERM (pkill, systemd) behaves like Ctrl+C, so the children are stopped too.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        while True:
            for name, p in running:
                if p.poll() is not None:
                    print(f"!! {name} exited with code {p.returncode}", flush=True)
                    running.remove((name, p))
                    break
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for _, p in running:
            p.terminate()
        for _, p in running:
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
