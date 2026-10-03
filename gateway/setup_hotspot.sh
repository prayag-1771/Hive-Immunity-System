#!/bin/sh
# Turn a Linux laptop / Raspberry Pi into the Hive gateway: a private 2.4 GHz WPA2
# hotspot (NetworkManager "shared" mode = DHCP + NAT) plus the nftables quarantine rules.
#
#   sudo sh gateway/setup_hotspot.sh <SSID> <PASSWORD> [wifi-interface]
#   sudo sh gateway/setup_hotspot.sh --down          # stop the hotspot, remove the rules
#
# 2.4 GHz and WPA2-PSK/CCMP only, because the ESP32 cannot join 5 GHz networks.
# The gateway gets 10.42.0.1/24; clients get 10.42.0.x by DHCP.
set -eu

CON=hive-hotspot
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

if [ "${1:-}" = "--down" ]; then
    nmcli connection down "$CON" 2>/dev/null || true
    nmcli connection delete "$CON" 2>/dev/null || true
    nft delete table inet hive 2>/dev/null || true
    echo "hotspot stopped, quarantine rules removed"
    exit 0
fi

SSID="${1:?usage: setup_hotspot.sh SSID PASSWORD [IFACE]}"
PASS="${2:?usage: setup_hotspot.sh SSID PASSWORD [IFACE]}"
IFACE="${3:-$(nmcli -t -f DEVICE,TYPE device | awk -F: '$2 == "wifi" { print $1; exit }')}"

if [ ${#PASS} -lt 8 ]; then
    echo "WPA2 password must be at least 8 characters" >&2
    exit 1
fi
if [ -z "$IFACE" ]; then
    echo "no Wi-Fi interface found (nmcli device)" >&2
    exit 1
fi

nmcli connection delete "$CON" >/dev/null 2>&1 || true
nmcli connection add type wifi ifname "$IFACE" con-name "$CON" autoconnect no ssid "$SSID"
nmcli connection modify "$CON" \
    802-11-wireless.mode ap 802-11-wireless.band bg \
    ipv4.method shared ipv6.method disabled \
    wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$PASS" \
    wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.group ccmp
nmcli connection up "$CON"

nft -f "$HERE/nft_rules.nft"

ADDR=$(ip -4 -o addr show "$IFACE" | awk '{ print $4 }')
echo "hotspot '$SSID' up on $IFACE, gateway address $ADDR"
echo "quarantine rules loaded: sudo nft list table inet hive"
