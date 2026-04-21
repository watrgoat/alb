#!/usr/bin/env python3
"""Plot per-backend packet latency over time.

In --simulate runs, the adapter synthesizes a mean packet latency per
backend using an M/M/1 sojourn-time model against the current
(sent, cap) pair and writes it into each snapshot. This plot reads
snapshots.jsonl and renders:

  - one subplot per backend: mean latency (µs) over time, with
    saturation cap overlaid as a dotted horizontal line so it's obvious
    when a backend flatlined under overload;
  - an aggregate subplot at the bottom: per-backend lines on a shared
    log axis so the latency spread during phase transitions is visible.

Output: latency-real.png in the same results dir.

Usage:
    python3 plot_latency.py <results_dir>
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

SATURATION_US = 100_000.0


def read_simulated_latency(path: Path) -> tuple[list[str], dict[str, dict[int, float]]]:
    """Return (ordered_backend_ips, per_ip_ts_to_latency_us)."""
    per_ip: dict[str, dict[int, float]] = defaultdict(dict)
    order: list[str] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = int(obj.get("t", obj.get("timestamp", 0)))
            for b in obj.get("backends", []):
                ip = b.get("ip")
                lat = b.get("latency_us")
                if ip is None or lat is None:
                    continue
                if ip not in per_ip:
                    order.append(ip)
                per_ip[ip][ts] = float(lat)
    return order, {k: dict(v) for k, v in per_ip.items()}


def read_schedule(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        return sorted(json.loads(path.read_text()),
                      key=lambda e: e["t_offset_sec"])
    except (json.JSONDecodeError, KeyError):
        return []


def read_hotswap_events(path: Path, start_ts: int) -> list[tuple[float, int]]:
    """Return [(seconds_since_start, cycle_number)] for each successful
    strategy install in the generator's latency log. These are the
    moments at which the ALB's `./strategies/libstrategy.so` was
    replaced — i.e. hot-swap events."""
    if not path.exists():
        return []
    out: list[tuple[float, int]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("status") != "installed":
                continue
            try:
                t = float(obj["t"]) - start_ts
                cyc = int(obj.get("cycle", 0))
            except (KeyError, ValueError, TypeError):
                continue
            out.append((t, cyc))
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: plot_latency.py <results_dir>", file=sys.stderr)
        return 2

    d = Path(sys.argv[1])
    snap_path = d / "snapshots.jsonl"
    start_path = d / "start_time.txt"
    sched_path = d / "caps_schedule.json"

    if not snap_path.exists() or not start_path.exists():
        print("missing snapshots.jsonl or start_time.txt — latency plot "
              "needs simulate-mode adapter history.", file=sys.stderr)
        return 1

    start_ts = int(start_path.read_text().strip())
    ips, per_ip = read_simulated_latency(snap_path)
    if not per_ip:
        print(f"no latency_us fields in {snap_path} — is the adapter "
              "running in --simulate mode?", file=sys.stderr)
        return 1

    schedule = read_schedule(sched_path)
    markers = [e["t_offset_sec"] for e in schedule]

    # hot-swap events come from the generator's own latency log
    swaps = read_hotswap_events(d / "latency.jsonl", start_ts)

    # common timestamp grid (union of all backends)
    all_ts = sorted({t for series in per_ip.values() for t in series})
    rel = [t - start_ts for t in all_ts]
    series = {
        ip: [per_ip[ip].get(t, None) for t in all_ts] for ip in ips
    }

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = len(ips)
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]

    fig, axes = plt.subplots(
        n + 1, 1,
        figsize=(13, 2.3 * (n + 1)),
        sharex=True,
        gridspec_kw={"height_ratios": [2] * n + [3]},
    )

    # hot-swap marker positioning: a row of down-pointing triangles along
    # the top of each subplot. on log-y axes, putting them at 80% of
    # the ceiling keeps them visible but clear of the saturation line.
    swap_ts = [t for t, _ in swaps]
    swap_y_top = SATURATION_US * 0.8

    def draw_hotswaps(ax):
        # thin vertical lines so spatial correlation with latency
        # dynamics is easy; triangles along the top mark the events
        # themselves so swap-heavy periods show up as dense clusters.
        for t in swap_ts:
            ax.axvline(t, color="#9467bd", linestyle="-",
                       linewidth=0.5, alpha=0.35, zorder=1)
        if swap_ts:
            ax.scatter(swap_ts, [swap_y_top] * len(swap_ts),
                       marker="v", color="#9467bd", s=18,
                       zorder=6, label=f"hot-swap ({len(swap_ts)})",
                       edgecolors="white", linewidths=0.3)

    # per-backend latency
    for i, ip in enumerate(ips):
        ax = axes[i]
        ys = series[ip]
        # saturation markers: where did latency hit the ceiling?
        sat_x = [x for x, y in zip(rel, ys) if y is not None and y >= SATURATION_US]
        finite_y = [y for y in ys if y is not None]
        color = colors[i % len(colors)]

        ax.plot(rel, ys, color=color, linewidth=1.8,
                label=f"mean latency ({ip})")
        ax.axhline(SATURATION_US, color="grey", linestyle=":", linewidth=0.9,
                   alpha=0.6, label="saturation ceiling (100ms)")
        if sat_x:
            ax.scatter(sat_x, [SATURATION_US] * len(sat_x),
                       color="#d62728", s=12, marker="x",
                       label="saturated (sent ≥ cap)", zorder=5)
        draw_hotswaps(ax)
        ax.set_yscale("log")
        # y-axis: from base latency (10µs) up through saturation
        ax.set_ylim(5.0, SATURATION_US * 1.5)
        ax.set_ylabel(f"backend {i}\n{ip}\nµs", fontsize=9)
        ax.grid(True, which="both", alpha=0.25)
        ax.legend(loc="upper right", fontsize=8, ncol=2, framealpha=0.92)
        for ts_off in markers:
            ax.axvline(ts_off, color="grey", linestyle=":", alpha=0.6)

    # aggregate subplot: all backends overlaid
    ax = axes[-1]
    for i, ip in enumerate(ips):
        ax.plot(rel, series[ip], color=colors[i % len(colors)],
                linewidth=1.6, label=ip)
    ax.axhline(SATURATION_US, color="grey", linestyle=":", linewidth=0.9,
               alpha=0.6, label="saturation ceiling")
    draw_hotswaps(ax)
    ax.set_yscale("log")
    ax.set_ylim(5.0, SATURATION_US * 1.5)
    ax.set_ylabel("all backends\nµs", fontsize=9)
    ax.set_xlabel("seconds since start", fontsize=10)
    ax.grid(True, which="both", alpha=0.25)
    ax.legend(loc="upper right", fontsize=8, ncol=min(4, n + 2))
    for ts_off in markers:
        ax.axvline(ts_off, color="grey", linestyle=":", alpha=0.6)

    fig.suptitle(f"Per-backend packet latency — {d.name}",
                 fontsize=13, y=0.997)
    fig.tight_layout(rect=(0, 0, 1, 0.987))

    out = d / "latency-real.png"
    fig.savefig(out, dpi=120)
    print(f"wrote {out}")

    # stderr summary per backend
    for ip in ips:
        finite = [v for v in series[ip] if v is not None]
        if not finite:
            continue
        finite_sorted = sorted(finite)
        p50 = finite_sorted[len(finite_sorted) // 2]
        p99 = finite_sorted[int(len(finite_sorted) * 0.99)]
        peak = max(finite_sorted)
        sat_frac = sum(1 for v in finite if v >= SATURATION_US) / len(finite)
        print(f"{ip}: p50={p50:.0f}µs  p99={p99:.0f}µs  peak={peak:.0f}µs  "
              f"saturated={sat_frac * 100:.1f}% of samples",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
