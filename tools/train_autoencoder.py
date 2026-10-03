"""Train the tiny on-device anomaly model: a 5 -> 3 -> 5 autoencoder in plain numpy.

Input: the per-window z-scores every node logs while healthy (data/windows/*.jsonl), i.e.
"how far is this second from what this device learned as normal". The autoencoder learns
to reconstruct normal windows; anything it cannot reconstruct is anomalous.

Exports the same weights twice:
  agent/model.json             used by the Python agents (--detector auto|autoencoder)
  firmware/hive_node/model.h   compiled into the ESP32 (HAVE_AE_MODEL 1)

  python tools/train_autoencoder.py
  python tools/train_autoencoder.py --hidden 3 --epochs 3000 --margin 3
"""

import argparse
import glob
import json
import os
import time

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_JSON = os.path.join(ROOT, "agent", "model.json")
MODEL_H = os.path.join(ROOT, "firmware", "hive_node", "model.h")
NF = 5
CLIP = 20.0


def load_windows(pattern):
    rows = []
    for path in sorted(glob.glob(pattern)):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    z = json.loads(line)["z"]
                except (ValueError, KeyError):
                    continue
                if len(z) == NF:
                    rows.append(z)
    return np.clip(np.array(rows, dtype=np.float64), -CLIP, CLIP)


def forward(p, x):
    h = np.tanh(x @ p["w1"] + p["b1"])
    return h, h @ p["w2"] + p["b2"]


def rmse(p, x):
    _, y = forward(p, x)
    return np.sqrt(np.mean((x - y) ** 2, axis=1))


def train(x, hidden, epochs, lr, seed):
    rng = np.random.default_rng(seed)
    p = {"w1": rng.normal(0, 0.5, (NF, hidden)), "b1": np.zeros(hidden),
         "w2": rng.normal(0, 0.5, (hidden, NF)), "b2": np.zeros(NF)}
    m = {k: np.zeros_like(v) for k, v in p.items()}
    v = {k: np.zeros_like(val) for k, val in p.items()}
    b1, b2, eps = 0.9, 0.999, 1e-8
    n = len(x)
    for t in range(1, epochs + 1):
        h, y = forward(p, x)
        dy = 2.0 * (y - x) / (n * NF)               # d(MSE)/dy
        g = {"w2": h.T @ dy, "b2": dy.sum(0)}
        dh = (dy @ p["w2"].T) * (1.0 - h ** 2)
        g["w1"] = x.T @ dh
        g["b1"] = dh.sum(0)
        for k in p:                                  # Adam
            m[k] = b1 * m[k] + (1 - b1) * g[k]
            v[k] = b2 * v[k] + (1 - b2) * g[k] ** 2
            p[k] -= lr * (m[k] / (1 - b1 ** t)) / (np.sqrt(v[k] / (1 - b2 ** t)) + eps)
    return p


def attack_like():
    """Representative attack windows in z-space (what a 50 msg/s junk flood looks like)."""
    return np.array([
        [40, 1, 20, 20, 0],    # malformed flood from one unknown sender
        [40, 1, 20, 0, 0],     # well-formed flood from an unknown sender
        [15, 1, 20, 20, 3],
        [8, 2, 10, 10, 1],     # a slower, partial-window attack
    ], dtype=np.float64).clip(-CLIP, CLIP)


def c_array(name, a):
    if a.ndim == 1:
        return f"static const float {name}[{a.shape[0]}] = {{{', '.join(f'{x:.7g}f' for x in a)}}};"
    rows = ",\n  ".join("{" + ", ".join(f"{x:.7g}f" for x in r) + "}" for r in a)
    return f"static const float {name}[{a.shape[0]}][{a.shape[1]}] = {{\n  {rows}}};"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=os.path.join(ROOT, "data", "windows", "*.jsonl"))
    ap.add_argument("--hidden", type=int, default=3)
    ap.add_argument("--epochs", type=int, default=3000)
    ap.add_argument("--lr", type=float, default=0.01)
    ap.add_argument("--margin", type=float, default=3.0,
                    help="threshold = margin x the 99.9th percentile of held-out normal error")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    x = load_windows(args.data)
    if len(x) < 200:
        raise SystemExit(f"only {len(x)} normal windows found under {args.data}; "
                         "run the nodes for a few minutes first (they log while healthy)")
    rng = np.random.default_rng(args.seed)
    idx = rng.permutation(len(x))
    split = int(len(x) * 0.8)
    train_x, held_x = x[idx[:split]], x[idx[split:]]

    p = train(train_x, args.hidden, args.epochs, args.lr, args.seed)
    err_train, err_held = rmse(p, train_x), rmse(p, held_x)
    threshold = float(max(np.percentile(err_held, 99.9) * args.margin, 0.5))
    err_attack = rmse(p, attack_like())
    false_alarm_rate = float(np.mean(err_held > threshold))
    size = 4 * sum(v.size for v in p.values())

    print(f"windows: {len(train_x)} train / {len(held_x)} held-out")
    print(f"normal error  : median {np.median(err_held):.3f}, p99.9 {np.percentile(err_held, 99.9):.3f}")
    print(f"threshold     : {threshold:.3f}  (held-out false alarms {false_alarm_rate:.2%})")
    print(f"attack windows: {', '.join(f'{e:.2f}' for e in err_attack)}"
          f"  -> min {err_attack.min() / threshold:.1f}x threshold")
    print(f"model size    : {size} bytes of weights ({NF}->{args.hidden}->{NF})")
    if err_attack.min() <= threshold:
        raise SystemExit("an attack window falls under the threshold: not exporting (try --margin lower)")

    model = {k: v.tolist() for k, v in p.items()}
    model.update(threshold=round(threshold, 4), clip=CLIP, hidden=args.hidden,
                 trained_on=len(train_x), created=time.strftime("%Y-%m-%d"))
    with open(MODEL_JSON, "w", encoding="utf-8", newline="\n") as f:
        json.dump(model, f, indent=1)
        f.write("\n")

    header = [
        "// GENERATED by tools/train_autoencoder.py -- tiny autoencoder for the on-chip detector.",
        f"// {NF}->{args.hidden}->{NF}, tanh hidden layer, trained on {len(train_x)} normal windows"
        f" ({time.strftime('%Y-%m-%d')}); {size} bytes of weights.",
        "#pragma once",
        "#define HAVE_AE_MODEL 1",
        f"#define AE_HIDDEN {args.hidden}",
        f"static const float AE_THRESHOLD = {threshold:.6g}f;",
        f"static const float AE_CLIP = {CLIP:.1f}f;",
        c_array("AE_W1", p["w1"]),
        c_array("AE_B1", p["b1"]),
        c_array("AE_W2", p["w2"]),
        c_array("AE_B2", p["b2"]),
        "",
    ]
    with open(MODEL_H, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header))
    print(f"wrote {os.path.relpath(MODEL_JSON, ROOT)} and {os.path.relpath(MODEL_H, ROOT)}")


if __name__ == "__main__":
    main()
