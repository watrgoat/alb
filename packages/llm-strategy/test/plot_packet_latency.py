#!/usr/bin/env python3
"""Plot REAL sampled per-packet processing latency over time.

Unlike plot_latency.py (which reads a synthetic M/M/1 mean-sojourn
estimate the adapter writes into each snapshot), this plotter reads a
CSV of real per-packet timings sampled inside the dispatch hot path.
Two producers emit the same schema:

  convergence_test --latency-samples <path>   # sim-time select() calls
  alb ... --latency-csv <path>                # real worker_main, when
                                              # Track B instrumentation
                                              # lands in strategy_loader.cpp

Schema: timestamp_sec,backend_idx,proc_ns  (one row per sampled packet).

Because sampling is low-rate ("a few samples per second"), we bin by
simulated-second and plot per-backend p50/p95/p99 per bucket. Sparse
buckets (<3 samples) are skipped so the percentile lines don't wobble
on individual measurements.

Usage:
    python3 plot_packet_latency.py <samples.csv> <out.png> \
        [--markers markers.csv] [--title "..."]
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Iterable


def load_samples(path: Path
                 ) -> tuple[list[int], dict[int, dict[int, list[int]]]]:
    """Return (ordered_backend_ids, per-backend-per-second-bucket list of
    proc_ns).

    Accepts two schemas:
      - simulator: timestamp_sec,backend_idx,proc_ns
      - production ALB: wall_us,lcore,backend_idx,proc_ns
    For the wall_us variant we bucket to whole seconds and rebase to the
    first sample so the plot x-axis starts at 0. lcore is ignored —
    samples across workers collapse into the same backend bucket.
    """
    per_b: dict[int, dict[int, list[int]]] = defaultdict(
        lambda: defaultdict(list))
    order: list[int] = []
    t0_us: int | None = None
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                bidx = int(row["backend_idx"])
                ns = int(row["proc_ns"])
            except (KeyError, ValueError):
                continue
            if "timestamp_sec" in row:
                try:
                    t = int(row["timestamp_sec"])
                except ValueError:
                    continue
            elif "wall_us" in row:
                try:
                    us = int(row["wall_us"])
                except ValueError:
                    continue
                if t0_us is None:
                    t0_us = us
                t = (us - t0_us) // 1_000_000
            else:
                continue
            if bidx not in per_b:
                order.append(bidx)
            per_b[bidx][t].append(ns)
    return order, {b: dict(v) for b, v in per_b.items()}


def percentile(xs: list[int], q: float) -> float:
    if not xs:
        return 0.0
    xs_sorted = sorted(xs)
    k = min(int(q * (len(xs_sorted) - 1)), len(xs_sorted) - 1)
    return float(xs_sorted[k])


def per_second_percentiles(buckets: dict[int, list[int]],
                           min_samples: int = 3,
                           ) -> tuple[list[int], list[float], list[float],
                                      list[float], list[int]]:
    """Return parallel lists (t_secs, p50_ns, p95_ns, p99_ns, n_samples)
    in timestamp order, skipping buckets with fewer than min_samples."""
    ts_sorted = sorted(buckets)
    ts, p50, p95, p99, n = [], [], [], [], []
    for t in ts_sorted:
        xs = buckets[t]
        if len(xs) < min_samples:
            continue
        ts.append(t)
        p50.append(percentile(xs, 0.50))
        p95.append(percentile(xs, 0.95))
        p99.append(percentile(xs, 0.99))
        n.append(len(xs))
    return ts, p50, p95, p99, n


def load_markers(path: Path) -> list[int]:
    """Accepts either a JSON caps-schedule (list of
    {t_offset_sec, caps_fraction|caps_pps, ...}) or a CSV with a
    `timestamp` column. Returns the list of marker timestamps, in
    whatever units the producer used — plotter overlays them as
    vertical lines against the `timestamp_sec` axis."""
    ts: list[int] = []
    if not path.exists():
        return ts
    suffix = path.suffix.lower()
    if suffix == ".json":
        import json
        try:
            obj = json.loads(path.read_text())
        except json.JSONDecodeError:
            return ts
        if isinstance(obj, list):
            for entry in obj:
                try:
                    ts.append(int(entry["t_offset_sec"]))
                except (KeyError, TypeError, ValueError):
                    continue
        return ts
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts.append(int(row["timestamp"]))
            except (KeyError, ValueError):
                continue
    return ts


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="plot real sampled per-packet processing latency")
    ap.add_argument("samples_csv", type=Path,
                    help="timestamp_sec,backend_idx,proc_ns")
    ap.add_argument("out_png", type=Path,
                    help="output PNG path")
    ap.add_argument("--markers", type=Path, default=None,
                    help="optional markers.csv — one vertical line per row")
    ap.add_argument("--title", type=str,
                    default="Per-backend packet processing latency (real, sampled)")
    args = ap.parse_args(list(argv) if argv is not None else None)

    order, per_b = load_samples(args.samples_csv)
    if not per_b:
        print(f"no samples in {args.samples_csv}")
        return 1

    markers = load_markers(args.markers) if args.markers else []

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = len(order)
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]

    fig, axes = plt.subplots(
        n + 1, 1,
        figsize=(13, 2.3 * (n + 1)),
        sharex=True,
        gridspec_kw={"height_ratios": [2] * n + [3]},
    )

    # per-backend subplots: p50 solid, p95 dashed, p99 dotted.
    for i, bidx in enumerate(order):
        ax = axes[i]
        ts, p50, p95, p99, ns_count = per_second_percentiles(per_b[bidx])
        color = colors[i % len(colors)]
        ax.plot(ts, p50, color=color, linewidth=1.6,
                label=f"backend {bidx} p50")
        ax.plot(ts, p95, color=color, linewidth=1.0, linestyle="--",
                alpha=0.9, label="p95")
        ax.plot(ts, p99, color=color, linewidth=1.0, linestyle=":",
                alpha=0.9, label="p99")
        ax.set_ylabel(f"backend {bidx}\nns", fontsize=9)
        ax.grid(True, which="both", alpha=0.25)
        ax.legend(loc="upper right", fontsize=8, ncol=3, framealpha=0.92)
        for ts_off in markers:
            ax.axvline(ts_off, color="grey", linestyle=":", alpha=0.6)

    # aggregate subplot: p99 lines per backend on shared log axis so the
    # tail behaviour at phase transitions is visible across all backends.
    ax = axes[-1]
    for i, bidx in enumerate(order):
        ts, _, _, p99, _ = per_second_percentiles(per_b[bidx])
        ax.plot(ts, p99, color=colors[i % len(colors)], linewidth=1.4,
                label=f"backend {bidx} p99")
    ax.set_yscale("log")
    ax.set_ylabel("all backends\np99 ns", fontsize=9)
    ax.set_xlabel("simulated second", fontsize=10)
    ax.grid(True, which="both", alpha=0.25)
    ax.legend(loc="upper right", fontsize=8, ncol=min(4, n))
    for ts_off in markers:
        ax.axvline(ts_off, color="grey", linestyle=":", alpha=0.6)

    # footer with total sample count so readers can judge bucket density
    total_samples = sum(
        sum(len(xs) for xs in per_b[bidx].values()) for bidx in order)
    fig.suptitle(f"{args.title}  ({total_samples:,} samples)",
                 fontsize=13, y=0.997)
    fig.tight_layout(rect=(0, 0, 1, 0.987))

    args.out_png.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out_png, dpi=120)
    print(f"wrote {args.out_png}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
