#!/bin/sh
# Raspberry Pi roles for the real-hardware demo, started at boot by hive-pi.service:
#   - the "Laptop B" immune node
#   - the gateway guardian, enforcing quarantine with nftables
#   - the attacker and the Wi-Fi dumb bulb, each on its own extra address
#   - the Bluetooth bulb (talks to the ESP32's Bluetooth hub)
#
# The attacker and bulb must not share an address with a node, so this script picks two
# free addresses in whatever /24 the hotspot hands out (checked with arping), adds them as
# temporary /32s, and restarts everything if the hotspot later changes the subnet.
# Override with environment variables in /etc/default/hive-pi.
set -u

REPO=${HIVE_REPO:-/home/pi/Hive-Immunity-System}
PY=${HIVE_PY:-/home/pi/hive-venv/bin/python}
IFACE=${HIVE_IFACE:-wlan0}
NODE=${HIVE_NODE:-lapB}
ROLES=${HIVE_ROLES:-"node:$NODE gateway attacker bulb blebulb"}

primary() {
    ip -4 -o addr show dev "$IFACE" scope global | awk '$4 !~ /\/32$/ { print $4; exit }' | cut -d/ -f1
}

log() { echo "hive-pi: $*"; }

# Remove our extra /32 addresses outside the /24 given (all of them when none is given).
drop_extra() {
    for a in $(ip -4 -o addr show dev "$IFACE" | awk '$4 ~ /\/32$/ { print $4 }'); do
        case "$a" in "${1:-none}".*) ;; *) ip addr del "$a" dev "$IFACE" && log "removed stale $a" ;; esac
    done
}

# Wait for a network.
while [ -z "$(primary)" ]; do sleep 2; done

# Only on the demo hotspot (the one the ESP32 is flashed for): never claim addresses or
# start the demo on someone else's network, such as a campus Wi-Fi the Pi also knows.
LAST=""
until MSG=$(cd "$REPO" && "$PY" tools/hive_up.py --check-network 2>&1); do
    if [ "$MSG" != "$LAST" ]; then
        log "$MSG; waiting for the demo hotspot"
        drop_extra ""
        LAST=$MSG
    fi
    sleep 10
done
ME=$(primary)
NET=${ME%.*}
log "on $IFACE as $ME"

# Drop extra addresses left over from a different hotspot subnet.
drop_extra "$NET"

pick() {
    for last in "$@"; do
        cand="$NET.$last"
        [ "$cand" = "$ME" ] && continue
        if ip -4 -o addr show dev "$IFACE" | grep -q " $cand/32"; then echo "$cand"; return 0; fi
        if arping -D -q -I "$IFACE" -c 2 "$cand"; then echo "$cand"; return 0; fi
    done
    return 1
}

ARGS=""
for role in $ROLES; do
    case "$role" in
        attacker)
            ATK=$(pick 166 167 168 169 170 171) || { log "no free address for the attacker"; exit 1; }
            ip addr add "$ATK/32" dev "$IFACE" 2>/dev/null
            ARGS="$ARGS attacker@$ATK" ;;
        bulb)
            BULB=$(pick 120 121 122 123 124 125) || { log "no free address for the bulb"; exit 1; }
            ip addr add "$BULB/32" dev "$IFACE" 2>/dev/null
            ARGS="$ARGS bulb@$BULB" ;;
        *) ARGS="$ARGS $role" ;;
    esac
done

NFT=""
case " $ROLES " in
    *" gateway "*)
        if nft -f "$REPO/gateway/nft_rules.nft"; then NFT="--nft"; else log "nftables rules failed to load: app-level quarantine only"; fi ;;
esac

cd "$REPO" || exit 1
log "starting:$ARGS (gateway $ME $NFT)"
# shellcheck disable=SC2086
"$PY" -u tools/hive_up.py $ARGS --gateway "$ME" $NFT &
CHILD=$!

# If the hotspot hands us a different address, start over with fresh extra addresses.
while kill -0 "$CHILD" 2>/dev/null; do
    sleep 10
    if [ "$(primary)" != "$ME" ]; then
        log "address changed, restarting"
        kill -TERM "$CHILD"
        wait "$CHILD"
        exit 1
    fi
done
wait "$CHILD"
