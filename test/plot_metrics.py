#!/usr/bin/env python3
"""Join tx-stats.csv (input) and traffic-stats.csv (output) on timestamp and plot.

Usage:
    python3 test/plot_metrics.py <results_dir>

Expects:
    <results_dir>/tx-stats.csv        columns: timestamp,pps_tx
    <results_dir>/traffic-stats.csv   columns: timestamp,ip,packets_delta

Writes:
    <results_dir>/metrics.png (and prints summary to stdout)
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path


def read_tx(path: Path) -> dict[int, int]:
    out: dict[int, int] = {}
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            out[int(row["timestamp"])] = int(row["pps_tx"])
    return out


def read_rx(path: Path) -> tuple[dict[int, int], dict[str, dict[int, int]]]:
    """Return (totals_by_ts, per_ip[ip][ts])."""
    totals: dict[int, int] = defaultdict(int)
    per_ip: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    with path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = int(row["timestamp"])
            ip = row["ip"]
            delta = int(row["packets_delta"])
            totals[ts] += delta
            per_ip[ip][ts] += delta
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

    # Trim TX samples to the collector's observation window: anything before
    # the first RX sample or after the last is a post-shutdown artifact
    # (e.g. the generator briefly unthrottled after ALB died).
    if rx_total:
        t_start = min(rx_total)
        t_end = max(rx_total)
        tx = {ts: v for ts, v in tx.items() if t_start <= ts <= t_end}

    # Normalise RX to pps. traffic-collector samples every 5s and records the
    # total delta across that interval; divide to get per-second rate.
    SAMPLE_INTERVAL_SEC = 5
    rx_total_pps = {ts: v / SAMPLE_INTERVAL_SEC for ts, v in rx_total.items()}
    rx_per_ip_pps = {
        ip: {ts: v / SAMPLE_INTERVAL_SEC for ts, v in series.items()}
        for ip, series in rx_per_ip.items()
    }

    # Summary
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

    fig, ax = plt.subplots(figsize=(10, 5))

    tx_xs = sorted(tx.keys())
    ax.plot(
        [t - t0 for t in tx_xs],
        [tx[t] for t in tx_xs],
        label="input (gen TX pps)",
        linewidth=2,
    )

    rx_xs = sorted(rx_total_pps.keys())
    ax.plot(
        [t - t0 for t in rx_xs],
        [rx_total_pps[t] for t in rx_xs],
        label="output (XDP RX pps, total)",
        linewidth=2,
    )

    for ip in sorted(rx_per_ip_pps):
        series = rx_per_ip_pps[ip]
        xs = sorted(series.keys())
        ax.plot(
            [t - t0 for t in xs],
            [series[t] for t in xs],
            label=f"output (XDP RX pps, {ip})",
            linestyle="--",
            alpha=0.7,
        )

    ax.set_xlabel("seconds since start")
    ax.set_ylabel("packets / second")
    ax.set_title(f"ALB throughput: {results_dir.name}")
    ax.grid(True, alpha=0.3)
    ax.legend(loc="best")

    out = results_dir / "metrics.png"
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    print(f"\nWrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
