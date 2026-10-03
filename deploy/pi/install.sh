#!/bin/sh
# One-time Raspberry Pi setup: Python venv with bleak, and the hive-pi service that starts
# the Pi's demo roles at every boot.
#
#   cd ~/Hive-Immunity-System && sudo sh deploy/pi/install.sh
#   journalctl -u hive-pi -f          # watch it
#   sudo systemctl disable --now hive-pi   # turn it off
#
# config/nodes.json must already be here (copy it from the machine that ran
# tools/provision_keys.py; it holds the shared keys).
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
USER_HOME=$(getent passwd "${SUDO_USER:-pi}" | cut -d: -f6)
VENV="$USER_HOME/hive-venv"

[ -f "$REPO/config/nodes.json" ] || { echo "missing $REPO/config/nodes.json" >&2; exit 1; }
command -v nft >/dev/null || apt-get install -y nftables
command -v arping >/dev/null || apt-get install -y iputils-arping

if [ ! -x "$VENV/bin/python" ]; then
    sudo -u "${SUDO_USER:-pi}" python3 -m venv "$VENV"
fi
sudo -u "${SUDO_USER:-pi}" "$VENV/bin/pip" install -q bleak

sed -e "s#/home/pi/Hive-Immunity-System#$REPO#g" "$HERE/hive-pi.service" > /etc/systemd/system/hive-pi.service
if [ ! -f /etc/default/hive-pi ]; then
    printf 'HIVE_REPO=%s\nHIVE_PY=%s\n' "$REPO" "$VENV/bin/python" > /etc/default/hive-pi
fi
systemctl daemon-reload
systemctl enable --now hive-pi
echo "hive-pi installed and started: journalctl -u hive-pi -f"
