"""Epidemic Meter: project the speed measured in the live demo onto a city of 10,000 devices.

This is a standard SIR (Susceptible / Infected / Recovered-immune) epidemic model, the same
kind used for disease curves and, in the research literature, for how IoT botnets spread. It
is driven by two numbers measured live on our three real devices, not guessed:

  t_detect  seconds from the first attack packet on a node to that node quarantining itself
  t_spread  seconds from that first detection to the last node becoming immune (vaccine spread)

From those we derive a recovery/immunity rate gamma and an infection rate beta, and run the
textbook SIR difference equations. Hive's whole job is to push the basic reproduction number
R0 = beta / gamma below 1, at which an outbreak dies out instead of taking the whole city.

Everything here is pure (no sockets, no clock), so it is unit-tested directly and the same
code serves the dashboard. It is always a SIMULATION, labelled as such on screen.
"""


def derive_params(t_detect, t_spread, attacker_fanout_per_s, contact_factor):
    """Map the measured demo seconds to (beta, gamma).

    The mapping is deliberately simple and monotonic, not academically exact (noted in
    DECISIONS.md): faster Hive -> higher gamma -> lower R0.

      gamma = 1 / (t_detect + t_spread)   a device becomes immune in about this many seconds,
                                          so it leaves the infectious pool at rate 1/time.
      beta  = attacker_fanout_per_s * contact_factor
                                          how many neighbours an infected device would infect
                                          per second (attacker aggressiveness, a demo constant).

    gamma is clamped to a small positive floor so "without Hive" (no detection at all) is a
    separate, explicit case handled by the caller passing gamma=0.
    """
    total = max(1e-6, t_detect + t_spread)
    gamma = 1.0 / total
    beta = max(0.0, attacker_fanout_per_s) * max(0.0, contact_factor)
    return beta, gamma


def simulate(n=10000, beta=1.0, gamma=0.5, i0=1, steps=400, dt=0.25):
    """Run discrete SIR for `n` devices and return the curves and headline numbers.

    newInf = beta * S * I / n * dt      (infection, mass-action)
    newRec = gamma * I * dt             (recovery into immunity)
    S -= newInf ; I += newInf - newRec ; R += newRec   (counts never go negative)

    Returns t/S/I/R lists (down-sampled for the chart), R0, peak and final infected counts.
    """
    n = max(1, int(n))
    i0 = min(max(0, i0), n)
    S, I, R = float(n - i0), float(i0), 0.0
    ts, Ss, Is, Rs = [], [], [], []
    peak = I
    for step in range(int(steps) + 1):
        ts.append(round(step * dt, 4))
        Ss.append(S)
        Is.append(I)
        Rs.append(R)
        peak = max(peak, I)
        new_inf = beta * S * I / n * dt if n else 0.0
        new_inf = min(new_inf, S)            # can't infect more than are susceptible
        new_rec = min(gamma * I * dt, I)     # can't recover more than are infected
        S -= new_inf
        I += new_inf - new_rec
        R += new_rec
        S = max(0.0, S)
        I = max(0.0, I)
        R = max(0.0, R)

    # None (not float("inf")) when there is no recovery: "Infinity" is not valid JSON and a
    # browser's response.json() rejects the whole payload. The page shows None as "∞".
    r0 = beta / gamma if gamma > 0 else None
    ever_infected = n - S          # susceptibles left untouched never caught it
    return {
        "t": ts, "S": Ss, "I": Is, "R": Rs,
        "R0": r0,
        "peak_infected": int(round(peak)),
        "final_infected": int(round(ever_infected)),
        "n": n,
    }


def project(timing, cfg):
    """Both curves (with and without Hive) from the latest live timing and the config.

    `timing` is {"t_detect": s, "t_spread": s}; `cfg` is the config's "epidemic" block.
    "Without Hive" is the same outbreak with no detection and no immunity (gamma = 0): the
    botnet spreads until it runs out of devices.
    """
    n = int(cfg.get("city_size", 10000))
    steps = int(cfg.get("sim_steps", 400))
    dt = float(cfg.get("dt", 0.25))
    fanout = float(cfg.get("attacker_fanout_per_s", 5))
    contact = float(cfg.get("contact_factor", 0.6))
    t_detect = max(0.0, float(timing["t_detect"]))
    t_spread = max(0.0, float(timing["t_spread"]))

    beta, gamma = derive_params(t_detect, t_spread, fanout, contact)
    with_hive = simulate(n=n, beta=beta, gamma=gamma, steps=steps, dt=dt)
    without_hive = simulate(n=n, beta=beta, gamma=0.0, steps=steps, dt=dt)

    saved = without_hive["final_infected"] - with_hive["final_infected"]
    return {
        "city_size": n,
        "params": {"t_detect": round(t_detect, 2), "t_spread": round(t_spread, 2),
                   "beta": round(beta, 4), "gamma": round(gamma, 4)},
        "with_hive": with_hive,
        "without_hive": without_hive,
        "saved": max(0, saved),
        "saved_pct": round(100.0 * max(0, saved) / n, 1) if n else 0.0,
        "contained": with_hive["R0"] < 1.0,
    }
