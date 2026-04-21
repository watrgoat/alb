#!/usr/bin/env python3
"""Plot convergence_test output as one subplot per backend.

Reads the CSV emitted by convergence_test (schema:
timestamp,backend_idx,ip,packets_sent,packets_missed,capacity) and the
markers CSV, produces a PNG with:

  - One subplot per backend (shared X axis).
  - Solid colored line: packets_sent (what the LB routed here).
  - Black dashed step line: processing_capacity_pps (target).
  - Red shaded region where sent > capacity (drops are happening).
  - Red dashed line: packets_missed (absolute count).
  - Vertical dotted markers at every capacity change, annotated across
    all subplots so the correspondence to each phase is obvious.

  - One bottom subplot: aggregate miss rate vs time (rolling mean), so
    the overall convergence story is readable in a single glance.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def load_csv(path: Path):
    rows = defaultdict(lambda: {"t": [], "sent": [], "missed": [], "cap": []})
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            b = int(row["backend_idx"])
            rows[b]["t"].append(int(row["timestamp"]))
            rows[b]["sent"].append(int(row["packets_sent"]))
            rows[b]["missed"].append(int(row["packets_missed"]))
            rows[b]["cap"].append(int(row["capacity"]))
    return dict(sorted(rows.items()))


def load_markers(path: Path):
    out = []
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            caps = [int(row[k]) for k in row if k.startswith("cap")]
            out.append((int(row["timestamp"]), caps))
    return out


def rolling_mean(xs, window):
    out = []
    for i in range(len(xs)):
        lo = max(0, i - window + 1)
        chunk = xs[lo : i + 1]
        out.append(sum(chunk) / len(chunk))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, type=Path)
    ap.add_argument("--markers", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--title", default="LLM-driven strategy convergence")
    args = ap.parse_args()

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    backends = load_csv(args.csv)
    markers = load_markers(args.markers)
    n = len(backends)

    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
    miss_color = "#d62728"
    cap_color = "#222222"

    fig, axes = plt.subplots(
        n + 1, 1,
        figsize=(13, 2.6 * (n + 1)),
        sharex=True,
        gridspec_kw={"height_ratios": [2] * n + [1]},
    )

    # shared y-limit across all backend subplots so absolute pps is
    # visually comparable. pick headroom above the largest sent or
    # capacity seen anywhere in the run.
    global_max = 0
    for series in backends.values():
        global_max = max(global_max, max(series["sent"]), max(series["cap"]))
    shared_ymax = global_max * 1.15

    # one subplot per backend
    for ax_idx, (bidx, series) in enumerate(backends.items()):
        ax = axes[ax_idx]
        t = series["t"]
        sent = series["sent"]
        missed = series["missed"]
        cap = series["cap"]
        color = colors[bidx % len(colors)]

        # capacity as thick dashed step — this is the target to track
        ax.step(t, cap, color=cap_color, linewidth=1.8, linestyle=(0, (6, 3)),
                where="post", label="capacity (target)", zorder=3)

        # red fill where sent exceeds capacity — drops are happening
        over = [max(0, s - c) for s, c in zip(sent, cap)]
        if any(v > 0 for v in over):
            ax.fill_between(
                t, cap, sent,
                where=[s > c for s, c in zip(sent, cap)],
                color=miss_color, alpha=0.18, step="post",
                label="over-capacity (drops)",
                interpolate=False, zorder=1,
            )

        # packets_sent — primary line
        ax.plot(t, sent, color=color, linewidth=2.0,
                label=f"sent (backend {bidx})", zorder=4)

        # packets_missed — secondary emphasis line, always visible
        ax.plot(t, missed, color=miss_color, linewidth=1.1,
                linestyle="--", alpha=0.85,
                label="missed", zorder=5)

        ax.set_ylim(0, shared_ymax)

        ax.set_ylabel(f"backend {bidx}\npps", fontsize=10)
        ax.grid(True, alpha=0.3)
        ax.legend(loc="upper right", fontsize=8, ncol=2, framealpha=0.92)

        # vertical markers at capacity changes
        for ts, _ in markers:
            ax.axvline(ts, color="grey", linestyle=":", alpha=0.6, zorder=2)

    # bottom subplot: aggregate miss rate (rolling 5s mean of per-second
    # miss_total / sent_total). makes the whole-system convergence
    # narrative readable at a glance.
    ax = axes[-1]
    times = next(iter(backends.values()))["t"]
    total_sent = [0] * len(times)
    total_miss = [0] * len(times)
    for series in backends.values():
        for i in range(len(times)):
            total_sent[i] += series["sent"][i]
            total_miss[i] += series["missed"][i]
    miss_rate = [
        (m / s) if s else 0.0 for m, s in zip(total_miss, total_sent)
    ]
    smoothed = rolling_mean(miss_rate, window=5)

    ax.fill_between(times, 0, smoothed, color=miss_color, alpha=0.25,
                    label="aggregate miss rate (5s rolling)")
    ax.plot(times, smoothed, color=miss_color, linewidth=1.6)
    ax.axhline(0.05, color="black", linestyle=":", linewidth=0.9,
               label="5% budget")
    ax.set_ylim(0, max(0.1, max(smoothed) * 1.2))
    ax.set_ylabel("miss rate", fontsize=10)
    ax.set_xlabel("time (s)", fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper right", fontsize=8)

    for ts, _ in markers:
        ax.axvline(ts, color="grey", linestyle=":", alpha=0.6)

    # annotate phases across the whole figure — labels anchored just
    # below the top subplot title so they don't overlap data.
    top_ax = axes[0]
    ylim = top_ax.get_ylim()
    for ts, caps in markers:
        top_ax.annotate(
            f"caps={caps}",
            xy=(ts, ylim[1]),
            xytext=(ts + 0.5, ylim[1] * 0.97),
            fontsize=8, color="grey",
            ha="left", va="top",
        )

    fig.suptitle(args.title, fontsize=13, y=0.995)
    fig.tight_layout(rect=(0, 0, 1, 0.985))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out, dpi=120)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
