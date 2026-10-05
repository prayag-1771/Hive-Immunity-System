"""Keep a Windows laptop on the demo hotspot: other saved Wi-Fi networks stop joining by themselves.

Windows leaves a Wi-Fi network that has no internet for a saved one that has (in our first
no-internet test it jumped from the hotspot to a campus network mid-demo). Before the demo:

  python tools/demo_wifi.py lock      # every other saved network: "connect manually"
  python tools/demo_wifi.py unlock    # afterwards: put back exactly what lock changed
  python tools/demo_wifi.py status

Nothing is forgotten or deleted; joining any network by hand still works. The hotspot's
name comes from the config (esp32.ssid). Windows only (netsh); English Windows output.
"""

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))
import hive_core as hc  # noqa: E402
import hive_net as net  # noqa: E402

RECORD = os.path.join(ROOT, "data", "wifi_locked.json")   # data/ is gitignored


def parse_profiles(text):
    """Profile names in `netsh wlan show profiles` output."""
    out, in_list = [], False
    for line in text.splitlines():
        if line.strip().startswith("User profiles"):
            in_list = True
        elif in_list and " : " in line:
            name = line.split(" : ", 1)[1].strip()
            if name:
                out.append(name)
    return out


def parse_auto(text):
    """True if `netsh wlan show profile name=X` says it joins by itself, None if unknown."""
    for line in text.splitlines():
        if line.strip().startswith("Connection mode"):
            return "automatically" in line.split(":", 1)[1]
    return None


def netsh(*args):
    r = subprocess.run(["netsh", "wlan", *args], capture_output=True, text=True, timeout=20)
    return r.returncode, r.stdout


def profiles():
    return parse_profiles(netsh("show", "profiles")[1])


def is_auto(name):
    return parse_auto(netsh("show", "profile", f"name={name}")[1])


def set_mode(name, mode):
    code, out = netsh("set", "profileparameter", f"name={name}", f"connectionmode={mode}")
    return code == 0


def load_record():
    try:
        with open(RECORD) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("lock", "unlock", "status"))
    ap.add_argument("--config", default=net.DEFAULT_CONFIG)
    args = ap.parse_args()
    if os.name != "nt":
        raise SystemExit("Windows only: on Linux, NetworkManager does not leave a network for lacking internet")
    hotspot = ((hc.load_config(args.config).get("esp32") or {}).get("ssid") or "").strip()
    if not hotspot:
        raise SystemExit("no hotspot named in the config (esp32.ssid)")

    if args.action == "lock":
        changed = load_record()
        for name in profiles():
            if name.strip() != hotspot and name not in changed and is_auto(name) and set_mode(name, "manual"):
                changed.append(name)
        os.makedirs(os.path.dirname(RECORD), exist_ok=True)
        with open(RECORD, "w") as f:
            json.dump(changed, f, indent=1)
        print(f"{len(changed)} other saved network(s) now join only by hand; '{hotspot}' is untouched.")
        print("Undo after the demo: python tools/demo_wifi.py unlock")
    elif args.action == "unlock":
        changed = load_record()
        failed = [name for name in changed if not set_mode(name, "auto")]
        if failed:
            with open(RECORD, "w") as f:
                json.dump(failed, f, indent=1)
            raise SystemExit(f"could not restore: {', '.join(failed)}")
        if os.path.exists(RECORD):
            os.remove(RECORD)
        print(f"{len(changed)} network(s) join by themselves again.")
    else:
        auto = [name for name in profiles() if name.strip() != hotspot and is_auto(name)]
        print(f"on: {', '.join(net.wifi_ssids() or []) or 'no Wi-Fi network'}; demo hotspot: '{hotspot}'")
        print(f"other saved networks that can pull this laptop away: {len(auto)}"
              + (" (run: python tools/demo_wifi.py lock)" if auto else ""))
        if load_record():
            print(f"locked by this tool: {len(load_record())} (undo: python tools/demo_wifi.py unlock)")


if __name__ == "__main__":
    main()
