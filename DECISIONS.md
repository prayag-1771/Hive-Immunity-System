# Decisions

Choices made while building, where the brief left room. Newest at the bottom.

1. **License: MIT.** The brief allowed MIT or Apache-2.0; MIT is shorter and equally
   accepted for the open-source track.
2. **Single-laptop simulation uses distinct loopback IPs.** Every simulated device binds
   its own `127.0.0.x` address (hub `.1`, esp32 `.2`, lapA `.3`, lapB `.4`, bulb `.20`,
   attacker `.66`). Blocking by source IP therefore behaves exactly as on the real LAN.
   Verified on Windows; Linux supports it too. macOS only has `127.0.0.1` unless aliases
   are added, so run the local demo on Windows or Linux.
