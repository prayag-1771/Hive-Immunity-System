# Hive Immune System — Upgrades Brief (Epidemic Meter + Decoy & Attacker Profile)

> Saved copy of the upgrade brief the team worked from. See README.md and DECISIONS.md
> for how these were actually built. Two features on top of the working Hive demo:
>
> - **Upgrade A — Epidemic Meter:** project the live-measured detection and spread speed
>   onto a city of 10,000 devices with a standard SIR model; show outbreak with vs without
>   Hive, and R0. Pure software, clearly labelled a simulation.
> - **Upgrade B — Decoy Trap + Attacker Profile:** a honeypot/tarpit. A flagged attacker is
>   routed into a fake slow "smart camera" that only ever replies to connections the
>   attacker makes to it, logs what they try, and builds an incident report. Observe-only:
>   nothing is ever sent toward the attacker, and the "attacker" is our own script on our
>   own hotspot.
>
> Non-negotiable safety: no hacking back, scanning, exploiting, deauth or jamming; no
> packet is ever initiated toward the attacker; the report flags a source, never a person.
