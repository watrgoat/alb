#!/usr/bin/env python3
"""Plot ALB input/output throughput and per-backend distribution.

Usage:
    python3 test/plot_metrics.py <results_dir>

Expects:
    <results_dir>/tx-stats.csv        columns: timestamp,pps_tx
    <results_dir>/traffic-stats.csv   columns: timestamp,ip,pps

Writes three figures to <results_dir>/:
    throughput.png      input (gen TX) vs output (ALB RX total), in Mpps
    per-backend.png     per-backend Mpps over time (absolute)
    backend-share.png   per-backend share of total RX (%), for adaptivity
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

PPS_TO_MPPS = 1e-6


def read_tx(path: Path) -> dict[int, int]:
    out: dict[int, int] = {}
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            out[int(row["timestamp"])] = int(row["pps_tx"])
    return out


def read_rx(path: Path) -> tuple[dict[int, int], dict[str, dict[int, int]]]:
    """Return (totals_by_ts, per_ip[ip][ts]) in pps."""
    totals: dict[int, int] = defaultdict(int)
    per_ip: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = int(row["timestamp"])
            ip = row["ip"]
            pps = int(row["pps"])
            totals[ts] += pps
            per_ip[ip][ts] += pps
    return dict(totals), {k: dict(v) for k, v in per_ip.items()}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    results_dir = Path(sys.argv[1])
    tx_path = results_dir / "tx-stats.csv"
    rx_path = results_dir / "traffic-stats.csv"

    if not tx_path.exists():
        print(f"Missing {tx_path}", file=sys.stderr)
        return 1
    if not rx_path.exists():
        print(f"Missing {rx_path}", file=sys.stderr)
        return 1

    tx = read_tx(tx_path)
    rx_total, rx_per_ip = read_rx(rx_path)

    # Trim TX to the collector's observation window; anything outside is a
    # post-shutdown artifact.
    if rx_total:
        t_start, t_end = min(rx_total), max(rx_total)
        tx = {ts: v for ts, v in tx.items() if t_start <= ts <= t_end}

    tx_total = sum(tx.values())
    rx_total_pkts = sum(rx_total.values())
    loss = (1 - rx_total_pkts / tx_total) if tx_total else 0.0

    print(f"Samples:  TX={len(tx)}  RX={len(rx_total)}")
    print(f"TX total packets:  {tx_total}")
    print(f"RX total packets:  {rx_total_pkts}")
    print(f"Loss:              {loss:.2%}")
    print(f"Per-backend RX totals:")
    for ip in sorted(rx_per_ip):
        print(f"  {ip:<16} {sum(rx_per_ip[ip].values())}")

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib not installed; skipping plot.", file=sys.stderr)
        print("Install with: pip install matplotlib", file=sys.stderr)
        return 0

    t0 = min(list(tx.keys()) + list(rx_total.keys()))

    def rel(ts_iterable):
        return [t - t0 for t in ts_iterable]

    # Union of all sample timestamps, for the per-backend share plot below.
    all_ts = sorted(set(rx_total.keys()))

    # --- 1. Throughput: input vs output -----------------------------------
    fig, ax = plt.subplots(figsize=(10, 4.5))
    tx_xs = sorted(tx.keys())
    ax.plot(
        rel(tx_xs),
        [tx[t] * PPS_TO_MPPS for t in tx_xs],
        label="input (gen TX)",
        linewidth=2,
    )
    rx_xs = sorted(rx_total.keys())
    ax.plot(
        rel(rx_xs),
        [rx_total[t] * PPS_TO_MPPS for t in rx_xs],
        label="output (ALB RX total)",
        linewidth=2,
    )
    ax.set_xlabel("seconds since start")
    ax.set_ylabel("throughput (Mpps)")
    ax.set_title(f"ALB throughput — {results_dir.name}  (loss {loss:.2%})")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)
    ax.legend(loc="best")
    fig.tight_layout()
    out1 = results_dir / "throughput.png"
    fig.savefig(out1, dpi=120)
    plt.close(fig)

    # --- 2. Per-backend absolute Mpps -------------------------------------
    fig, ax = plt.subplots(figsize=(10, 4.5))
    for ip in sorted(rx_per_ip):
        series = rx_per_ip[ip]
        xs = sorted(series.keys())
        ax.plot(
            rel(xs),
            [series[t] * PPS_TO_MPPS for t in xs],
            label=ip,
            linewidth=1.8,
        )
    ax.set_xlabel("seconds since start")
    ax.set_ylabel("per-backend throughput (Mpps)")
    ax.set_title(f"Per-backend RX — {results_dir.name}")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)
    ax.legend(loc="best", title="backend IP")
    fig.tight_layout()
    out2 = results_dir / "per-backend.png"
    fig.savefig(out2, dpi=120)
    plt.close(fig)

    # --- 3. Per-backend share of total (for adaptivity) -------------------
    # Shows the fraction of traffic going to each backend per second. When
    # the ALB adapts (e.g. one backend gets throttled), its share drops
    # while the others rise — easier to spot than absolute pps.
    fig, ax = plt.subplots(figsize=(10, 4.5))
    for ip in sorted(rx_per_ip):
        series = rx_per_ip[ip]
        xs = []
        ys = []
        for t in all_ts:
            total = rx_total.get(t, 0)
            if total <= 0:
                continue
            xs.append(t - t0)
            ys.append(100.0 * series.get(t, 0) / total)
        ax.plot(xs, ys, label=ip, linewidth=1.8)
    ax.set_xlabel("seconds since start")
    ax.set_ylabel("share of total RX (%)")
    ax.set_title(f"Per-backend share — {results_dir.name}")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 100)
    ax.legend(loc="best", title="backend IP")
    fig.tight_layout()
    out3 = results_dir / "backend-share.png"
    fig.savefig(out3, dpi=120)
    plt.close(fig)

    print(f"\nWrote {out1}")
    print(f"Wrote {out2}")
    print(f"Wrote {out3}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
