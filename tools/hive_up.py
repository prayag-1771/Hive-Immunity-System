"""Start this machine's roles for the real-network demo, with prefixed logs. Ctrl+C stops all.

  python tools/hive_up.py dashboard node:lapA gateway              # Laptop A
  python tools/hive_up.py node:lapB                                # Laptop B
  python tools/hive_up.py attacker bulb --gateway 10.42.0.1        # Laptop C
  sudo python3 tools/hive_up.py node:lapB attacker@10.229.175.166 bulb@10.229.175.120 --gateway 10.229.175.4

Roles:
  dashboard        dashboard + normal-traffic hub (HTTP on --http, default 127.0.0.1)
  node:<id>        an immune node from the config (lapA, lapB, ...)
  gateway          the dumb-device guardian (add --nft on a Linux gateway, as root)
  attacker[@ip]    the scenario daemon; @ip binds a specific (extra) address
  bulb[@ip]        the simulated dumb bulb; @ip binds a specific (extra) address
"""

import argparse
import os
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def command(role, args):
    py = [sys.executable, "-u"]
    name, _, bind = role.partition("@")
    kind, _, node = name.partition(":")
    cfg = ["--config", args.config]
    if kind == "dashboard":
        return "dashboard", py + ["dashboard/server.py", "--http", args.http] + cfg
    if kind == "node" and node:
        return node, py + ["agent/hive_agent.py", "--node", node, "--detector", args.detector] + cfg
    if kind == "gateway":
        return "gateway", py + ["gateway/guardian.py"] + cfg + (["--nft"] if args.nft else [])
    if kind == "attacker":
        return "attacker", py + ["tools/scenarios.py", "serve"] + cfg + (["--bind", bind] if bind else [])
    if kind == "bulb":
        extra = (["--bind", bind] if bind else []) + (["--gateway", args.gateway] if args.gateway else [])
        return "bulb", py + ["tools/dumb_device.py"] + cfg + extra
    raise SystemExit(f"unknown role '{role}' (see --help)")


def pump(name, proc, width):
    for line in iter(proc.stdout.readline, b""):
        sys.stdout.write(f"{name:<{width}} | {line.decode(errors='replace').rstrip()}\n")
        sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roles", nargs="+")
    ap.add_argument("--config", default=os.path.join(ROOT, "config", "nodes.json"))
    ap.add_argument("--http", default="127.0.0.1", help="dashboard HTTP bind (0.0.0.0 to share on the LAN)")
    ap.add_argument("--detector", default="auto", choices=("auto", "zscore", "autoencoder"))
    ap.add_argument("--gateway", help="gateway IP for the bulb (default: from config, else broadcast)")
    ap.add_argument("--nft", action="store_true", help="gateway also enforces with nftables (Linux, root)")
    args = ap.parse_args()
    if not os.path.exists(args.config):
        raise SystemExit(f"{args.config} missing: copy config/nodes.json from the machine that ran "
                         "tools/provision_keys.py (same keys on every machine)")

    procs = [command(r, args) for r in args.roles]
    width = max(len(n) for n, _ in procs)
    running = []
    for name, cmd in procs:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        running.append((name, p))
        threading.Thread(target=pump, args=(name, p, width), daemon=True).start()
    print(f"started: {', '.join(n for n, _ in procs)}  (Ctrl+C stops all)", flush=True)
    try:
        while running:
            for name, p in list(running):
                if p.poll() is not None:
                    print(f"!! {name} exited with code {p.returncode}", flush=True)
                    running.remove((name, p))
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
