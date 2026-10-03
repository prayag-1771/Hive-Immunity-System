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
   vaccines go unicast to every configured peer. On the LAN, `broadcast: "auto"` sends to
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
    ESP32 events have no `ts` (it has no clock); the dashboard stamps them on arrival.
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
