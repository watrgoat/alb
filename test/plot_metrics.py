#!/usr/bin/env python3
"""Plot gen/ALB/collector metrics for a results dir.

Usage:
    python3 test/plot_metrics.py <results_dir>

Inputs (any/all may be present):
    <dir>/tx-stats.csv        columns: timestamp,pps_tx              (gen TX)
    <dir>/alb-stats.csv       columns: timestamp,port,rx_pps,tx_pps,
                                       imissed,ierrors               (ALB)
    <dir>/traffic-stats.csv   columns: timestamp,ip,pps              (XDP sink)

Writes PNGs (only for the inputs that exist):
    throughput.png       gen TX vs ALB ingress RX vs ALB egress TX (Mpps)
    alb-drops.png        per-port imissed/ierrors (pps) — ALB overrun signal
    per-backend.png      per-backend Mpps (when collector CSV is present)
    backend-share.png    per-backend share of total RX (%), for adaptivity
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
        for row in csv.DictReader(f):
            out[int(row["timestamp"])] = int(row["pps_tx"])
    return out


def read_rx(path: Path) -> tuple[dict[int, int], dict[str, dict[int, int]]]:
    totals: dict[int, int] = defaultdict(int)
    per_ip: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    with path.open() as f:
        for row in csv.DictReader(f):
            ts = int(row["timestamp"])
            ip = row["ip"]
            pps = int(row["pps"])
            totals[ts] += pps
            per_ip[ip][ts] += pps
    return dict(totals), {k: dict(v) for k, v in per_ip.items()}


def read_alb(path: Path) -> dict[int, dict[int, dict[str, int]]]:
    """Return alb[port][ts] = {rx_pps, tx_pps, imissed, ierrors}."""
    alb: dict[int, dict[int, dict[str, int]]] = defaultdict(dict)
    with path.open() as f:
        for row in csv.DictReader(f):
            ts = int(row["timestamp"])
            port = int(row["port"])
            alb[port][ts] = {
                "rx_pps": int(row["rx_pps"]),
                "tx_pps": int(row["tx_pps"]),
                "imissed": int(row["imissed"]),
                "ierrors": int(row["ierrors"]),
            }
    return {p: dict(v) for p, v in alb.items()}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    results_dir = Path(sys.argv[1])
    tx_path = results_dir / "tx-stats.csv"
    rx_path = results_dir / "traffic-stats.csv"
    alb_path = results_dir / "alb-stats.csv"

    tx = read_tx(tx_path) if tx_path.exists() else {}
    alb = read_alb(alb_path) if alb_path.exists() else {}
    rx_total: dict[int, int] = {}
    rx_per_ip: dict[str, dict[int, int]] = {}
    if rx_path.exists():
        rx_total, rx_per_ip = read_rx(rx_path)

    if not tx and not alb and not rx_total:
        print(
            f"No CSVs found in {results_dir} (need at least one of "
            "tx-stats.csv, alb-stats.csv, traffic-stats.csv).",
            file=sys.stderr,
        )
        return 1

    # Determine the observation window: anything outside is trimmed.
    # Prefer ALB timestamps if available — those are the most reliable
    # "system is running steady" window.
    if alb:
        alb_ts = sorted({ts for p in alb.values() for ts in p})
        t_start, t_end = alb_ts[0], alb_ts[-1]
    elif rx_total:
        t_start, t_end = min(rx_total), max(rx_total)
    else:
        t_start, t_end = min(tx), max(tx)

    tx = {ts: v for ts, v in tx.items() if t_start <= ts <= t_end}

    # --- summary ----------------------------------------------------------
    print(f"Window: {t_start}..{t_end}  ({t_end - t_start + 1}s)")
    if tx:
        tx_mean = sum(tx.values()) / len(tx) * PPS_TO_MPPS
        print(f"gen TX mean: {tx_mean:.2f} Mpps  ({len(tx)} samples)")
    if alb:
        for port in sorted(alb):
            series = alb[port]
            rx_mean = (
                sum(s["rx_pps"] for s in series.values()) / len(series) * PPS_TO_MPPS
            )
            tx_mean = (
                sum(s["tx_pps"] for s in series.values()) / len(series) * PPS_TO_MPPS
            )
            imiss = sum(s["imissed"] for s in series.values())
            ierr = sum(s["ierrors"] for s in series.values())
            print(
                f"ALB port {port}: rx {rx_mean:.2f} Mpps  tx {tx_mean:.2f} Mpps  "
                f"imissed {imiss}  ierrors {ierr}"
            )
    if rx_total:
        rx_mean = sum(rx_total.values()) / len(rx_total) * PPS_TO_MPPS
        print(f"collector RX mean: {rx_mean:.2f} Mpps")
        for ip in sorted(rx_per_ip):
            print(f"  {ip:<16} {sum(rx_per_ip[ip].values())}")

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib not installed; skipping plots.", file=sys.stderr)
        return 0

    # Common time origin across every series available.
    all_ts: list[int] = list(tx.keys())
    for p in alb.values():
        all_ts.extend(p.keys())
    all_ts.extend(rx_total.keys())
    t0 = min(all_ts)

    def rel(ts_iter):
        return [t - t0 for t in ts_iter]

    written: list[Path] = []

    # --- 1. Throughput: gen TX vs ALB ingress RX vs ALB egress TX ---------
    # This is the headline "can ALB keep up?" plot. All three lines should
    # track each other at the target rate if the ALB is not dropping.
    fig, ax = plt.subplots(figsize=(10, 4.5))
    if tx:
        xs = sorted(tx.keys())
        ax.plot(
            rel(xs),
            [tx[t] * PPS_TO_MPPS for t in xs],
            label="gen TX (input)",
            linewidth=2,
        )
    # Port 0 = ingress (P2), port 1 = egress (P3) by ALB's -a order.
    if 0 in alb:
        xs = sorted(alb[0].keys())
        ax.plot(
            rel(xs),
            [alb[0][t]["rx_pps"] * PPS_TO_MPPS for t in xs],
            label="ALB port 0 RX (ingress)",
            linewidth=2,
        )
    if 1 in alb:
        xs = sorted(alb[1].keys())
        ax.plot(
            rel(xs),
            [alb[1][t]["tx_pps"] * PPS_TO_MPPS for t in xs],
            label="ALB port 1 TX (egress)",
            linewidth=2,
        )
    if rx_total:
        xs = sorted(rx_total.keys())
        ax.plot(
            rel(xs),
            [rx_total[t] * PPS_TO_MPPS for t in xs],
            label="collector RX (sink)",
            linewidth=1.5,
            linestyle="--",
            alpha=0.7,
        )
    ax.set_xlabel("seconds since start")
    ax.set_ylabel("throughput (Mpps)")
    ax.set_title(f"ALB throughput — {results_dir.name}")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(bottom=0)
    ax.legend(loc="best")
    fig.tight_layout()
    out = results_dir / "throughput.png"
    fig.savefig(out, dpi=120)
    plt.close(fig)
    written.append(out)

    # --- 2. ALB drops: imissed / ierrors (pps) ----------------------------
    # imissed = NIC ring overflow because a worker didn't poll fast enough.
    # If this is ~0 at target rate, ALB is handling it. If it climbs, the
    # ALB is the bottleneck — not the generator or any downstream component.
    if alb:
        fig, ax = plt.subplots(figsize=(10, 4.5))
        for port in sorted(alb):
            series = alb[port]
            xs = sorted(series.keys())
            ax.plot(
                rel(xs),
                [series[t]["imissed"] for t in xs],
                label=f"port {port} imissed",
                linewidth=1.8,
            )
            if any(series[t]["ierrors"] for t in xs):
                ax.plot(
                    rel(xs),
                    [series[t]["ierrors"] for t in xs],
                    label=f"port {port} ierrors",
                    linewidth=1.2,
                    linestyle=":",
                )
        ax.set_xlabel("seconds since start")
        ax.set_ylabel("drops (packets/second)")
        ax.set_title(f"ALB NIC drops — {results_dir.name}")
        ax.grid(True, alpha=0.3)
        ax.set_ylim(bottom=0)
        ax.legend(loc="best")
        fig.tight_layout()
        out = results_dir / "alb-drops.png"
        fig.savefig(out, dpi=120)
        plt.close(fig)
        written.append(out)

    # --- 3. Per-backend absolute Mpps (only if collector ran) -------------
    if rx_per_ip:
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
        out = results_dir / "per-backend.png"
        fig.savefig(out, dpi=120)
        plt.close(fig)
        written.append(out)

    # --- 4. Per-backend share of total RX (%) -----------------------------
    if rx_per_ip and rx_total:
        fig, ax = plt.subplots(figsize=(10, 4.5))
        ts_list = sorted(rx_total.keys())
        for ip in sorted(rx_per_ip):
            series = rx_per_ip[ip]
            xs, ys = [], []
            for t in ts_list:
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
        out = results_dir / "backend-share.png"
        fig.savefig(out, dpi=120)
        plt.close(fig)
        written.append(out)

    print()
    for p in written:
        print(f"Wrote {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
