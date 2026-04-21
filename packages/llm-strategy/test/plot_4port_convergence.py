#!/usr/bin/env python3
"""Plot convergence on the REAL 4-port ALB pipeline.

Unlike the simulator plot (plot_convergence.py), the inputs here are the
CSVs emitted by the live pipeline's XDP collector + the capacity
schedule the adapter was configured with.

Inputs (all from $OUTDIR, the first positional arg):
  traffic-stats.csv    timestamp,ip,pps        (real measured per-backend rate)
  caps_schedule.json   [{t_offset_sec, caps_pps:[...]}]
  start_time.txt       unix ts treated as t=0 for the schedule
  tx-stats.csv         timestamp,pps_tx        (optional, total TX rate)
  snapshots.jsonl      adapter history         (optional, for miss overlay)

Outputs:
  convergence-real.png    one subplot per backend (shared Y), + aggregate
                          measured-vs-capacity summary at the bottom.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def read_traffic(path: Path) -> dict[str, dict[int, int]]:
    """Return per-IP map of timestamp -> pps, as observed by the collector."""
    per_ip: dict[str, dict[int, int]] = defaultdict(dict)
    with path.open() as f:
        for row in csv.DictReader(f):
            per_ip[row["ip"]][int(row["timestamp"])] = int(row["pps"])
    return {k: dict(v) for k, v in per_ip.items()}


def read_simulated_snapshots(path: Path) -> dict[str, dict[int, int]] | None:
    """Read per-IP sent-pps timeseries from the adapter's JSONL history,
    converting delta-over-window counters back to per-second rates.
    Returns None if the file doesn't exist or isn't in simulate format."""
    if not path.exists():
        return None
    per_ip: dict[str, dict[int, int]] = defaultdict(dict)
    per_ip_miss: dict[str, dict[int, int]] = defaultdict(dict)
    try:
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                ts = int(obj.get("t", obj.get("timestamp", 0)))
                win = float(obj.get("window_sec", 1.0)) or 1.0
                for b in obj.get("backends", []):
                    ip = b["ip"]
                    pps = int(b["packets_sent"] / win)
                    per_ip[ip][ts] = pps
                    per_ip_miss[ip][ts] = int(b["packets_missed"] / win)
    except (json.JSONDecodeError, KeyError, ValueError):
        return None
    if not per_ip:
        return None
    return {
        "sent": {k: dict(v) for k, v in per_ip.items()},
        "miss": {k: dict(v) for k, v in per_ip_miss.items()},
    }


def read_config_ips(config_path: Path) -> list[str]:
    """Parse backend IPs (in order) from the project's YAML config. matches
    the adapter's parser so the plot and the adapter agree on ordering."""
    return re.findall(r'ip:\s*"([^"]+)"', config_path.read_text())


def read_tx(path: Path) -> dict[int, int]:
    out: dict[int, int] = {}
    with path.open() as f:
        for row in csv.DictReader(f):
            out[int(row["timestamp"])] = int(row["pps_tx"])
    return out


def read_schedule(path: Path) -> list[dict]:
    return sorted(json.loads(path.read_text()), key=lambda e: e["t_offset_sec"])


def resolve_caps(entry: dict, n_backends: int,
                 baseline_total_pps: float) -> list[int]:
    """Resolve a schedule entry to absolute per-backend caps. Handles
    both `caps_pps` (absolute) and `caps_fraction` (× baseline)."""
    if "caps_pps" in entry:
        caps = [int(x) for x in entry["caps_pps"]]
    elif "caps_fraction" in entry:
        caps = [int(f * baseline_total_pps) for f in entry["caps_fraction"]]
    else:
        caps = [0] * n_backends
    # pad/truncate to n_backends
    return list(caps[:n_backends]) + [0] * max(0, n_backends - len(caps))


def schedule_step(schedule: list[dict], n_backends: int, ts_rel: list[int],
                  baseline_total_pps: float) -> list[list[int]]:
    """Return per-timestamp caps for each backend by walking the schedule."""
    if not schedule:
        return [[0] * n_backends for _ in range(len(ts_rel))]
    out: list[list[int]] = []
    cur = resolve_caps(schedule[0], n_backends, baseline_total_pps)
    sidx = 0
    for t in ts_rel:
        while (sidx + 1 < len(schedule)
               and schedule[sidx + 1]["t_offset_sec"] <= t):
            sidx += 1
            cur = resolve_caps(schedule[sidx], n_backends, baseline_total_pps)
        out.append(list(cur))
    return out


def infer_baseline(per_ip: dict[str, dict[int, int]], start_ts: int,
                   calibration_sec: int = 10,
                   min_pps: float = 100_000.0) -> float:
    """Fallback when the adapter's baseline_pps.txt is missing. Walks
    the CSV from start_ts and returns the first window's total pps that
    exceeds min_pps. Mirrors the adapter's latching logic."""
    timestamps = sorted({t for d_ in per_ip.values() for t in d_})
    for t in timestamps:
        if t < start_ts:
            continue
        lo, hi = t - calibration_sec, t
        samples_per_ip = {
            ip: [per_ip[ip][s] for s in range(lo, hi) if s in per_ip[ip]]
            for ip in per_ip
        }
        per_ip_avg = [sum(v) / len(v) for v in samples_per_ip.values() if v]
        total = sum(per_ip_avg)
        if total >= min_pps:
            return total
    return 1_000_000.0  # last-ditch fallback matches adapter's default


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: plot_4port_convergence.py <results_dir>", file=sys.stderr)
        return 2

    d = Path(sys.argv[1])
    traffic_csv = d / "traffic-stats.csv"
    tx_csv = d / "tx-stats.csv"
    sched_path = d / "caps_schedule.json"
    start_path = d / "start_time.txt"
    # the orchestrator copies the caller's config into the results dir as
    # caps_schedule.json; the backend list still comes from the ALB config.
    # resolve the config the same way the orchestrator points ALB at it.
    config_path = (d / "config-4port.yaml")
    if not config_path.exists():
        config_path = Path(__file__).resolve().parents[3] / "test" / "config-4port.yaml"

    # traffic-stats.csv is only required when we're NOT in simulate mode;
    # simulate runs never populate it.
    have_sim_jsonl = (d / "snapshots.jsonl").exists()
    if not sched_path.exists() or not start_path.exists():
        print("missing caps_schedule.json or start_time.txt", file=sys.stderr)
        return 1
    if not traffic_csv.exists() and not have_sim_jsonl:
        print("need either traffic-stats.csv (real mode) or snapshots.jsonl "
              "(simulate mode)", file=sys.stderr)
        return 1

    start_ts = int(start_path.read_text().strip())
    schedule = read_schedule(sched_path)

    # prefer the adapter's simulated snapshots — in --simulate mode, the
    # feedback signal visible to the controller IS the simulation, and the
    # plot is most useful when it shows the same view. fall back to the
    # real collector CSV otherwise.
    snapshots_path = d / "snapshots.jsonl"
    sim = read_simulated_snapshots(snapshots_path)
    per_ip_miss_sim: dict[str, dict[int, int]] = {}
    data_source = "collector (real)"
    if sim is not None:
        per_ip = sim["sent"]
        per_ip_miss_sim = sim["miss"]
        data_source = "simulated (from current weights)"
    else:
        per_ip = read_traffic(traffic_csv) if traffic_csv.exists() else {}
    tx = read_tx(tx_csv) if tx_csv.exists() else {}

    # always render one subplot per configured backend, even if the
    # collector never logged traffic for it — the absence is itself a
    # signal (e.g. a broken hash that sends 100% of traffic to one
    # backend shows up as two empty subplots, not as a missing subplot).
    ips = read_config_ips(config_path)
    if not ips:
        print(f"no backends in {config_path}; falling back to CSV-observed IPs",
              file=sys.stderr)
        ips = sorted(per_ip.keys())
    if not ips:
        print("no backends to plot", file=sys.stderr)
        return 1

    # Aligned timestamp grid. Use the collector's timestamps if available;
    # if the CSV is empty (e.g. collector didn't log anything), span the
    # schedule's total duration so we still get the capacity step lines.
    if per_ip:
        all_ts = sorted({t for d_ in per_ip.values() for t in d_})
    else:
        last_off = schedule[-1]["t_offset_sec"] if schedule else 0
        all_ts = [start_ts + t for t in range(0, last_off + 60)]
    rel_ts = [t - start_ts for t in all_ts]

    # per-backend pps aligned to all_ts (0-fill gaps — including for
    # backends that appear in config but not in the collector CSV).
    series_pps: dict[str, list[int]] = {}
    for ip in ips:
        series = per_ip.get(ip, {})
        series_pps[ip] = [series.get(t, 0) for t in all_ts]

    # resolve fractional caps using the adapter's latched baseline, so
    # the plot and the adapter agree on the absolute pps numbers. if the
    # baseline file is missing (older run, or adapter never calibrated)
    # fall back to re-deriving from the CSV.
    baseline_path = d / "baseline_pps.txt"
    if baseline_path.exists():
        try:
            baseline_total_pps = float(baseline_path.read_text().strip())
        except ValueError:
            baseline_total_pps = infer_baseline(per_ip, start_ts)
    else:
        baseline_total_pps = infer_baseline(per_ip, start_ts)

    # capacity schedule stepped onto the same grid
    cap_ts = schedule_step(schedule, len(ips), rel_ts, baseline_total_pps)
    series_cap: dict[str, list[int]] = {
        ip: [cap_ts[i][idx] for i in range(len(all_ts))] for idx, ip in enumerate(ips)
    }

    # markers: capacity-change events, labeled with resolved absolute caps
    markers = [
        (e["t_offset_sec"], resolve_caps(e, len(ips), baseline_total_pps))
        for e in schedule
    ]

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = len(ips)
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]
    miss_color = "#d62728"
    cap_color = "#222222"
    MPPS = 1e-6

    fig, axes = plt.subplots(
        n + 1, 1,
        figsize=(13, 2.6 * (n + 1)),
        sharex=True,
        gridspec_kw={"height_ratios": [2] * n + [1]},
    )

    # shared y across backend subplots — absolute Mpps comparison is the point
    global_max = 0
    for ip in ips:
        global_max = max(global_max, max(series_pps[ip] or [0]),
                         max(series_cap[ip] or [0]))
    shared_ymax = global_max * MPPS * 1.15 if global_max else 1.0

    for ax_idx, ip in enumerate(ips):
        ax = axes[ax_idx]
        sent = [v * MPPS for v in series_pps[ip]]
        cap = [v * MPPS for v in series_cap[ip]]
        # miss series (simulated data only) — this is the explicit "drops"
        # signal the controller sees, separate from the over-cap area fill
        miss = [v * MPPS for v in [per_ip_miss_sim.get(ip, {}).get(t, 0)
                                    for t in all_ts]] if per_ip_miss_sim else []
        color = colors[ax_idx % len(colors)]

        ax.step(rel_ts, cap, color=cap_color, linewidth=1.8,
                linestyle=(0, (6, 3)), where="post",
                label="synthetic capacity", zorder=3)

        ax.fill_between(
            rel_ts, cap, sent,
            where=[s > c for s, c in zip(sent, cap)],
            color=miss_color, alpha=0.18, step="post",
            label="over-capacity (synthetic drops)",
            interpolate=False, zorder=1,
        )

        ax.plot(rel_ts, sent, color=color, linewidth=2.0,
                label=f"sent ({ip})", zorder=4)

        if miss and any(m > 0 for m in miss):
            ax.plot(rel_ts, miss, color=miss_color, linewidth=1.1,
                    linestyle="--", alpha=0.85, label="missed", zorder=5)

        ax.set_ylim(0, shared_ymax)
        ax.set_ylabel(f"backend {ax_idx}\n{ip}\n(Mpps)", fontsize=9)
        ax.grid(True, alpha=0.3)
        ax.legend(loc="upper right", fontsize=8, ncol=3, framealpha=0.92)

        for ts_off, _ in markers:
            ax.axvline(ts_off, color="grey", linestyle=":", alpha=0.6, zorder=2)

    # bottom: aggregate observed vs aggregate capacity vs gen TX
    ax = axes[-1]
    total_sent = [sum(series_pps[ip][i] for ip in ips) for i in range(len(all_ts))]
    total_cap = [sum(series_cap[ip][i] for ip in ips) for i in range(len(all_ts))]
    ax.plot(rel_ts, [v * MPPS for v in total_sent], color="black", linewidth=1.8,
            label="total observed (sum of backends)")
    ax.step(rel_ts, [v * MPPS for v in total_cap], color=cap_color, linewidth=1.4,
            linestyle=(0, (6, 3)), where="post", label="total capacity")

    if tx:
        tx_rel = sorted(tx.keys())
        ax.plot([t - start_ts for t in tx_rel], [tx[t] * MPPS for t in tx_rel],
                color="#9467bd", linewidth=1.2, linestyle="--", alpha=0.8,
                label="gen TX (input rate)")

    ax.set_ylabel("total\n(Mpps)", fontsize=9)
    ax.set_xlabel("seconds since start", fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.legend(loc="upper right", fontsize=8)
    for ts_off, _ in markers:
        ax.axvline(ts_off, color="grey", linestyle=":", alpha=0.6)

    # annotations on top subplot
    top_ax = axes[0]
    ylim_top = top_ax.get_ylim()
    for ts_off, caps in markers:
        cap_str = "[" + ", ".join(f"{c/1e6:g}M" for c in caps) + "]"
        top_ax.annotate(
            f"caps={cap_str}",
            xy=(ts_off, ylim_top[1]),
            xytext=(ts_off + 0.5, ylim_top[1] * 0.97),
            fontsize=8, color="grey",
            ha="left", va="top",
        )

    fig.suptitle(f"ALB convergence — {data_source}  ({d.name})",
                 fontsize=13, y=0.995)
    fig.tight_layout(rect=(0, 0, 1, 0.985))

    out = d / "convergence-real.png"
    fig.savefig(out, dpi=120)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
