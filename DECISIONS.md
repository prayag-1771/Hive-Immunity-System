# Decisions

Choices made while building, where the brief left room. Newest at the bottom.

1. **License: MIT.** The brief allowed MIT or Apache-2.0; MIT is shorter and equally
   accepted for the open-source track.
2. **Single-laptop simulation uses distinct loopback IPs.** Every simulated device binds
   its own `127.0.0.x` address (hub `.1`, esp32 `.2`, lapA `.3`, lapB `.4`, bulb `.20`,
   attacker `.66`). Blocking by source IP therefore behaves exactly as on the real LAN.
   Verified on Windows; Linux supports it too. macOS only has `127.0.0.1` unless aliases
   are added, so run the local demo on Windows or Linux.
3. **Loopback has no broadcast**, so `config/local.json` sets `broadcast: null` and
   vaccines go unicast to every configured peer. On the LAN, `broadcast: "auto"` (the
   default) sends to
   the /24 directed broadcast *and* 255.255.255.255 (Windows may send the latter out of the
   wrong network card). Receivers silently drop an identical second copy, so duplicates
   never count as replays.
4. **The attacker is a daemon, triggered by signed messages from the dashboard.** Attacks
   must come from an address that isn't the hub (the hub is a protected, trusted sender),
   so the dashboard buttons can't just run the attack themselves. The same signed-trigger
   approach drives the dumb-bulb simulator.
5. **"Attack the cure" uses a provisioned `rogue` issuer.** Showing the quorum and
   autoimmune defences needs *validly signed* vaccines from a misbehaving device, so the
   config contains a `rogue` key standing in for a compromised Hive device. The forged and
   tampered cases use keys nobody has.
6. **The gateway is a vaccine issuer (`gateway` key).** When it quarantines a dumb device
   it also warns the Hive nodes. With quorum 2 its report alone leaves them at *pending
   1/2*, which is the safe default.
7. **Learning starts at the first hub command, not at boot.** Learning an empty network
   would make normal hub traffic look like an attack later.
8. **An empty window keeps the learned mean message size.** Otherwise a quiet second
   reads as "mean size 0", a 13-sigma event, and at ~3 messages/s that happens every
   ~25 s. Found during testing; covered by a 10-minute no-false-alarm test.
9. **The hub always counts as a known sender**, even at an address learned after a
   restart. Saved baselines would otherwise flag a hub that got a new DHCP address.
10. **Control messages carry a sequence number** (`ctrl` gained a `seq` field, the
    dashboard's millisecond clock) so a captured reset can't be replayed. `ctrl` is checked
    before the quarantine filter, because it is signed and the dashboard must be able to
    heal a quarantined node.
11. **Events may carry a `target` field** (the IP concerned) in addition to the brief's
    fields, so the dashboard computes *time to immunity* from structured data, not text.
    The dashboard stamps **every** event with its own clock on arrival and ignores the
    sender's `ts`: the ESP32 has no clock, and an offline Raspberry Pi (no RTC battery, no
    NTP at the venue) can drift, which would corrupt *time to immunity*.
12. **Status messages may exceed 512 bytes** (the node limit applies to messages *to*
    nodes). The dashboard accepts up to 4 KB; real statuses stay under ~600 bytes, and both
    test suites check that a status with full tables still fits in one datagram.
13. **Time to immunity** runs from the attacker's first packet (its `attack_started`
    event) to the moment every online node has the attacker blocked, by detection or by
    adopted vaccine.
14. **Dashboard: Server-Sent Events, with `?poll` as a fallback.** Polling also makes
    headless screenshots possible.
15. **Gateway quarantine: app-level always, nftables optional (`--nft`).** The nftables
    set drops forwarded traffic and input from the device, except DHCP and the guardian's
    sink port. Wi-Fi clients on the same access point are relayed by the driver rather
    than routed, so this isolates the device from the internet and the gateway, which is
    the botnet/DDoS case. The README says so.
16. **The hotspot is forced to 2.4 GHz WPA2-CCMP**, because the ESP32 can't join 5 GHz.
17. **The ESP32 firmware is tested on a PC.** `firmware/test` compiles the real sketch
    against small mocks of Arduino, Wi-Fi, UDP and NVS and replays the Python test
    scenarios, so logic bugs surface before the board is on the desk.
18. **The ESP32 toolchain comes from Espressif's mirror** (`dl.espressif.com/github_assets`)
    when GitHub release downloads stall. arduino-cli still checks every archive against
    the official index's SHA-256.
19. **"Explain incident" defaults to the Ollama model tag `gemma4`**, set under `explain`
    in the config (`url`, `model`, `timeout_s`). The exact Gemma 4 tag must be checked
    against the installed Ollama (`ollama list`). Without a model the dashboard falls back
    to a template sentence, so the button never fails on stage.
20. **Bluetooth: the ESP32 is the hub (a GATT server); the device connects to it.** The
    Raspberry Pi plays the Bluetooth bulb with bleak, which is easy to script on Linux.
    Many real bulbs work the other way round; the README says so. Reports are tiny text
    (`name:seq:light`, at most 20 bytes, so they fit the default BLE MTU). The hub learns
    per-address report rate and malformed share, cuts the link with
    `esp_ble_gap_disconnect` (the library's `disconnect()` only closes the GATT session)
    and refuses that address until a signed reset. The Bluetooth callbacks run in the
    Bluetooth task, so they only push into a locked queue; `loop()` does the logic.
21. **The firmware uses the `huge_app` partition** (3 MB app, no OTA): Wi-Fi plus Bluedroid
    is 1.67 MB, more than the default 1.3 MB. NVS stays at 0x9000, so learned baselines
    survive the switch.
22. **Wi-Fi with Bluetooth:** modem sleep is on (Espressif's coexistence rule), the
    Bluetooth hub starts only once Wi-Fi is up (or after 15 s), and a Wi-Fi attempt gets
    20 s before it is restarted. Without Bluetooth, modem sleep stays off.
23. **Never send outside the local segment.** Found on real hardware: the hotspot dropped,
    the laptop rejoined a campus network, and the hub kept sending to the old addresses
    through the campus router. `hive_net.send` now asks the routing table (a UDP
    `connect()` sends nothing) and drops anything that would leave this machine's /24.
24. **The gateway runs on the Pi with nftables**, started at boot by `hive-pi.service`,
    which also picks the attacker's and the bulb's extra addresses with `arping`
    duplicate detection in whatever subnet the hotspot hands out.
25. **Provisioning remembers the ESP32's Wi-Fi, LED and Bluetooth settings** in
    `nodes.json` (gitignored), so a plain re-run never writes placeholder Wi-Fi into
    `secrets.h`.
26. **Gemma model: `gemma4:e2b-it-qat`**, the smallest Gemma 4 build in Ollama's library
    (4.3 GB). It replaces the unverified `gemma4` tag of decision 19. Ollama runs from its
    portable zip, so nothing is installed system-wide.
27. **Bluetooth on real hardware needed four fixes**, all found with `btmon` and serial logs:
    the hub starts its controller LE-only (BlueZ otherwise tried classic Bluetooth),
    prefers Bluetooth for radio time (`esp_coex_preference_set`), doesn't advertise during
    link setup, and the Pi uses 100-150 ms connection intervals with a 4 s supervision
    timeout so a new link survives the ESP32's Wi-Fi time-slicing.
28. **The simulated Bluetooth bulb had two event-flag bugs**: a disconnect callback that read
    a reassigned variable, and BlueZ's internal connection retries reported as disconnects
    on the same client. Both made the bulb drop its own healthy link.
29. **Gemma requests set `think: false`.** Gemma 4 otherwise spends its token budget on hidden
    reasoning and returns an empty answer. The first load on a machine takes minutes while
    CUDA compiles its kernels, so the dashboard warms the model in the background, keeps it
    loaded, and answers from the template until it is ready. Ollama runs with a 4 GB CUDA
    kernel cache (`CUDA_CACHE_MAXSIZE`) so later starts are fast.
