# Hive Immunity System

[![CI](https://github.com/prayag-1771/Hive-Immunity-System/actions/workflows/ci.yml/badge.svg)](https://github.com/prayag-1771/Hive-Immunity-System/actions/workflows/ci.yml)

**A digital immune system for IoT devices.** Smart devices detect attacks with a tiny
on-device model, quarantine themselves, and share signed **vaccines** ("block this
sender") so their neighbours block the attacker *before it reaches them*. Dumb devices
that cannot run our code (bulbs, plugs, cameras) are protected by the router/gateway,
which quarantines them.

Peer-to-peer. Offline. No cloud. Runs on a ₹500 ESP32.

> Big companies buy an immune system for their network. We put one inside every tiny
> device — so they protect each other, with no cloud and no expensive box.

![Live dashboard mid-demo: the ESP32 and Laptop B detected the attack, Laptop A adopted their vaccines and blocked the attacker on its first packet, and the gateway isolated an infected bulb](docs/dashboard.png)

---

## The problem

- About **21.1 billion** connected IoT devices by the end of 2025. Most are "dumb"
  (bulbs, plugs, cameras, sensors) with no antivirus and rare updates.
- Hijacked devices power record botnets. **Aisuru** is estimated at **1–4 million**
  compromised devices (home IoT, video recorders, routers), spreading mainly through
  outdated firmware and default passwords, and has launched record DDoS attacks
  (**31.4 Tbps**).
- New laws only fix **future** devices: the UK banned default passwords in 2024, and the
  EU Cyber Resilience Act's main obligations apply from December 2027. Billions of devices
  already deployed stay exposed.
- Enterprise "immune system" products (e.g. Darktrace's *Enterprise Immune System*) learn
  normal behaviour and flag anomalies, but they are expensive network/cloud appliances. A
  home, shop, farm or small factory can't afford them, and they don't run **inside** cheap
  devices.
- When one cheap device is attacked today, **its neighbours learn nothing**. The attacker
  simply moves on to the next one.

## The idea

| Body | Hive |
|---|---|
| Cells know what "normal" looks like | Each device runs a tiny model that learns its own normal traffic |
| An infected cell isolates itself | The device enters **quarantine** and only trusts known senders |
| Immune memory and vaccines | The device broadcasts a signed **vaccine**: "block sender X" |
| Others become immune before infection | Neighbours add X to their block list in advance |
| Protection against autoimmunity | Devices that spam vaccines lose trust |

One system covers three kinds of device:

1. **Smart devices** (ESP32, or anything that runs Hive) protect themselves on-device.
2. **Dumb Wi-Fi devices** are watched by the **gateway**, which learns each device's
   normal behaviour and isolates a misbehaving one. In a real deployment this runs on an
   OpenWrt router; in the demo a laptop or Raspberry Pi plays the router.
3. **Bluetooth devices**: the paired hub cuts off a misbehaving device (roadmap).

### Poison-proof vaccines

"Can't the vaccine itself be hacked?" Every defence below is implemented and shown live in
the demo's *Attack the cure* step:

- **Data only, fixed schema, size-limited** (≤ 300 bytes, checked before parsing). A
  vaccine is never code and never free text that gets executed.
- **Block-only.** A vaccine can only *add* a block rule. It can never unblock, open
  anything, change config or update firmware. The worst a fake vaccine can do is cause a
  temporary unnecessary block, never a takeover.
- **Signed** by the issuing device (HMAC-SHA256). Forged or tampered vaccines are rejected.
- **Replay-protected** with a strictly increasing sequence number per issuer.
- **Second opinion (quorum):** a device adopts a vaccine from others only when **two
  different issuers** report the same target. Its own detection is enough for itself.
- **Rate-limited (autoimmune):** an issuer that sends too many vaccines is distrusted for
  a while, and its pending votes are dropped.
- **Expiry (TTL):** blocks expire, so mistakes heal on their own.
- **Protected targets:** no vaccine can target the hub/gateway or the receiving device.

### What is new, honestly

- **Not new:** learning normal behaviour and quarantining devices at network level
  (Darktrace, Firewalla, IoT Sentinel).
- **New:** the immune system lives **inside cheap devices**, devices **vaccinate each other
  peer-to-peer, offline, with no cloud**, and the vaccines are **poison-proof**. A 2025
  review notes that collaborative intrusion detection has not yet been implemented on
  resource-constrained devices.

---

## Architecture

```mermaid
flowchart LR
    subgraph LAN["Private hotspot LAN (no internet needed)"]
        HUB["Hub + dashboard<br/>(laptop A)"]
        ESP["ESP32 node<br/>on-chip model"]
        A["Laptop A node"]
        B["Laptop B node"]
        GW["Gateway guardian<br/>(laptop A or Pi)"]
        BULB["Dumb bulb<br/>(simulated)"]
        ATK["Attacker<br/>(scripted, laptop C)"]
    end
    HUB -- "normal commands (UDP 47000)" --> ESP & A & B
    ESP & A & B -- "status + events (UDP 47002)" --> HUB
    ESP <-. "signed vaccines (broadcast UDP 47001)" .-> A
    A <-. "vaccines" .-> B
    B <-. "vaccines" .-> ESP
    BULB -- "telemetry (UDP 47003)" --> GW
    GW -. "vaccine" .-> A
    ATK -- "attack traffic" --> ESP
```

**Every node, every second:** count the inbound messages and compute five features:
messages per second, distinct senders, unknown-sender ratio, malformed ratio and mean
size. While **learning** (the first 20 s of hub traffic) it records the mean and spread of
each feature and which senders are normal. After that it **scores** each window: by
default the largest z-score, or with the trained model, the reconstruction error of a tiny
5→3→5 autoencoder. Two anomalous windows in a row mean **quarantine**:

1. Block the culprit (the busiest unknown sender in the window).
2. Broadcast a signed vaccine against it.
3. Only trust known senders until things have been calm for 30 s.

**Every vaccine received** goes through the cheapest checks first: size → schema →
issuer known and not distrusted → sequence number → signature → rate limit → protected
target → quorum. Every rejection is counted and shown on the dashboard.

The same logic exists twice, and the tests keep the two in step:
[agent/hive_core.py](agent/hive_core.py) for laptops, and
[firmware/hive_node/hive_node.ino](firmware/hive_node/hive_node.ino) for the ESP32.

| Message | Direction | Purpose |
|---|---|---|
| `cmd` | hub → node | normal traffic: `ping`, `light_on`, `light_off`, `status` |
| `status` | node → dashboard, 1 Hz | state, score, features, counters, block list, pending votes |
| `event` | node → dashboard | quarantine, vaccine issued/adopted/rejected, healed, first packet blocked |
| `vax` | node → broadcast | `{issuer, seq, rule:"block", target, ttl, reason, sig}` |
| `ctrl` | dashboard → node | signed `reset` / `relearn` |

All messages are compact JSON over UDP. A vaccine's signature is
`HMAC-SHA256(issuer key, JSON without sig, sorted keys, no spaces)`, and a fixed test
vector checks the Python and C implementations against `openssl`.

---

## Quick start: the whole demo on one laptop

Python 3.10+ and nothing else. No internet needed.

```sh
python tools/provision_keys.py        # once: generates keys + configs (gitignored)
python tools/run_local.py --open      # dashboard at http://localhost:8080
```

`run_local.py` starts the dashboard and hub, three immune nodes (an ESP32 stand-in,
Laptop A, Laptop B), the gateway guardian, a dumb bulb and the attacker. Each one gets its
own `127.0.0.x` address, so blocking by sender address works exactly as on a real
network. Wait about 20 s for the tiles to turn green, then use the buttons or keys
`1`–`3`, `b`, `c`, `r`.

Run the tests:

```sh
python -m pytest tests                 # Python core: detection + every vaccine defence
sh firmware/test/run_host_test.sh      # ESP32 firmware on a PC (Linux/WSL, needs g++ + OpenSSL)
```

## Real hardware demo

| Device | Role | Runs |
|---|---|---|
| ESP32 | smart node with on-chip model | `firmware/hive_node` |
| Laptop A (Linux preferred) | gateway + node + dashboard/hub | `setup_hotspot.sh`, `guardian.py`, `hive_agent.py --node lapA`, `dashboard/server.py` |
| Laptop B | second smart node (gives a real quorum of 2) | `hive_agent.py --node lapB` |
| Laptop C or Raspberry Pi | attacker + dumb bulb | `scenarios.py serve`, `dumb_device.py` |

1. **Hotspot** on the gateway (2.4 GHz, because the ESP32 has no 5 GHz):
   `sudo sh gateway/setup_hotspot.sh HiveNet <password>`. A phone hotspot also works; then
   run the guardian without `--nft`. Never use venue Wi-Fi.
2. **Keys:** `python tools/provision_keys.py --ssid HiveNet --password <password> --led-pin 2`,
   then copy `config/nodes.json` to every laptop (the keys are the same everywhere).
3. **ESP32:** open `firmware/hive_node/hive_node.ino` in Arduino IDE (ESP32 core 3.x,
   ArduinoJson 7) or use arduino-cli, then flash it. Its LED blinks slowly while learning,
   follows the hub's light commands when healthy, and blinks fast when quarantined.

   ```sh
   arduino-cli core install esp32:esp32 --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
   arduino-cli lib install ArduinoJson
   arduino-cli compile --fqbn esp32:esp32:esp32 firmware/hive_node
   arduino-cli upload  --fqbn esp32:esp32:esp32 -p COM5 firmware/hive_node   # or /dev/ttyUSB0
   arduino-cli monitor -p COM5 -c baudrate=115200
   ```
4. **Start the roles:**
   - Laptop A: `python dashboard/server.py --http 0.0.0.0`,
     `python agent/hive_agent.py --node lapA` and `sudo python3 gateway/guardian.py --nft`
   - Laptop B: `python agent/hive_agent.py --node lapB`
   - Laptop C: `python tools/scenarios.py serve` and `python tools/dumb_device.py`
5. Open the dashboard on the projector and wait for all the tiles to turn green.

Baselines are saved (Python: `data/state/`, ESP32: flash), so restarts skip learning.

### Smaller setups

- **No third laptop:** the Raspberry Pi takes the attacker and dumb-bulb roles. The
  attacker must not share an address with the hub or a node, so it can't run on Laptop A
  or Laptop B.
- **Only two immune nodes** (e.g. the ESP32 and Laptop A): provision with `--quorum 1`, so
  one report is enough. Attacking the ESP32 then makes Laptop A immune straight away, and
  attacking Laptop A shows *blocked instantly*.
- **Pi as the gateway:** Raspberry Pi OS (Bookworm) uses NetworkManager, so
  `setup_hotspot.sh` and `guardian.py --nft` work there unchanged.

### Troubleshooting

- **A Windows laptop never shows up, or is stuck on "waiting for hub":** the Windows
  firewall is dropping UDP. Accept the "allow Python" prompt for *Private* networks and
  set the hotspot network's profile to Private.
- **The ESP32 doesn't appear:** it only joins 2.4 GHz Wi-Fi. Open the serial monitor at
  115200 baud: it prints its IP address, and typing `s` prints its state.
- **False alarms after moving to a new network:** press **Relearn** (or type `r` on the
  ESP32's serial monitor) so every node learns the new normal.
- **A screen or proxy that breaks live updates:** open `http://<dashboard>:8080/?poll`,
  which polls instead of streaming.

## Demo script (about 3 minutes)

![The seven demo steps on the one-laptop simulation](docs/demo.gif)

| Step | Press | What the judges see |
|---|---|---|
| 1 | — | Green tiles: ESP32, Laptop A, Laptop B and the dumb bulb. "Everything is normal." |
| 2 | **Attack ESP32** | The ESP32 turns red and its LED blinks fast. A vaccine flies to the others, which show *pending 1/2*. |
| 3 | **Attack Laptop B** | Laptop B detects the attack and sends a second vaccine. Laptop A reaches quorum and turns **immune**. *Time to immunity* stops. |
| 4 | **Attack Laptop A** | **BLOCKED INSTANTLY**: the first packet is dropped and no quarantine is needed. |
| 5 | **Infect dumb bulb** | The gateway sees the bulb flooding and the bulb turns red: *isolated by the gateway*. |
| 6 | **Attack the cure** | Forged, tampered, oversized, replayed, hub-targeting and spammed vaccines are all rejected, and the checklist lights up. |
| 7 | **Reset** | Everything heals back to green without restarting. |

Let a judge press the attack button. **Explain incident** asks a local open model
(Gemma through Ollama, if it is running) to narrate what happened, and falls back to a
template.

## Honest limits

- Hive **contains** infected dumb devices; it doesn't clean them.
- An attacker who carefully mimics normal traffic can slip through. The model only knows
  "normal versus not normal".
- The demo identifies senders by IP address and signs with per-node HMAC keys provisioned
  in advance. Production would use per-device asymmetric keys (Ed25519/ECDSA) generated
  on-chip and protected by flash encryption and secure boot.
- Wi-Fi clients on the same access point talk through the radio, not the router, so the
  gateway's firewall isolates a dumb device from the internet and the gateway, not from
  every neighbour.
- Bluetooth-only and SIM-card devices are only partly covered (roadmap).

## Roadmap

OpenWrt router package · Bluetooth hub enforcement · on-chip key generation and secure
boot · federated improvement of the tiny model · neighbourhood-wide vaccine sharing between
homes.

## Repository layout

```
agent/        hive_core.py (shared logic), hive_agent.py (laptop node), hub.py, model.json
firmware/     hive_node/ (ESP32 sketch, signing, model.h), test/ (PC harness + mocks)
dashboard/    server.py (stdlib HTTP + SSE), index.html (offline, no CDN)
gateway/      guardian.py, setup_hotspot.sh, nft_rules.nft
tools/        provision_keys.py, run_local.py, scenarios.py, dumb_device.py, train_autoencoder.py
tests/        pytest: HMAC vector, vaccine pipeline, detection
```

Safety: every "attack" is a simulation aimed at our own devices on our own private
hotspot. The dumb-bulb simulator only names addresses from 198.18.0.0/15 (reserved for
benchmarking, never routed) inside its messages, and sends them only to the gateway.

## Sources

- Cloudflare — Aisuru-Kimwolf botnet: https://www.cloudflare.com/learning/ddos/glossary/aisuru-kimwolf-botnet/
- IoT statistics (IoT Analytics, Nokia, Cloudflare, via Swif.ai): https://www.swif.ai/blog/iot-security-statistics
- UK default-password ban: https://www.helpnetsecurity.com/2024/04/29/uk-enacts-iot-cybersecurity-law/
- EU Cyber Resilience Act: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- Darktrace Enterprise Immune System: https://www.esecurityplanet.com/products/darktrace-enterprise-immune-system/
- 2025 review — collaborative intrusion detection not yet implemented on resource-constrained devices: https://www.sciencedirect.com/science/article/pii/S2214212625001644

## License

MIT — see [LICENSE](LICENSE).
