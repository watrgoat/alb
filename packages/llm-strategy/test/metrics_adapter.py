#!/usr/bin/env python3
"""Bridge the real 4-port pipeline's collector CSV into the MetricsSnapshot
schema the generator consumes.

Real backends in the 4-port test don't actually drop packets — they all
point at the same physical P4 NIC. To drive the LLM convergence loop on
real hardware, we synthesize a per-backend capacity limit on top of the
measured rates: miss = max(0, observed_pps - cap_pps). That turns an
uncapped multiplexer into a capacitated one for the controller's
purposes.

Run as a long-lived process. Every --interval seconds it reads the tail
of the collector's traffic-stats.csv, computes the current capacity
from the schedule (relative to --start-time), emits a snapshot JSON,
and sleeps.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path


def read_backend_ips(config_path: Path) -> list[str]:
    """Extract backend IPs in order from the project's YAML config.

    We avoid a YAML dep by grepping — the project's configs are small
    and use the fixed `ip: "..."` shape.
    """
    text = config_path.read_text()
    return re.findall(r'ip:\s*"([^"]+)"', text)


def load_schedule(path: Path) -> list[dict]:
    """Schedule JSON. Each entry has `t_offset_sec` plus either:
        - caps_pps:      [C0, C1, C2]    (absolute pps — host-specific)
        - caps_fraction: [f0, f1, f2]    (fraction of observed baseline total)
    caps_fraction is preferred: the adapter auto-calibrates a baseline
    from the first window after it sees non-trivial traffic, so the same
    schedule works on any host regardless of throughput ceiling.
    """
    entries = json.loads(path.read_text())
    return sorted(entries, key=lambda e: e["t_offset_sec"])


def active_entry(schedule: list[dict], elapsed_sec: float) -> dict:
    current = schedule[0]
    for entry in schedule:
        if entry["t_offset_sec"] <= elapsed_sec:
            current = entry
        else:
            break
    return current


def caps_at(schedule: list[dict], elapsed_sec: float,
            baseline_total_pps: float | None,
            fallback_total_pps: float) -> list[int]:
    """Return per-backend capacity in pps for the current schedule phase.

    If the entry has caps_pps, return verbatim. If it has caps_fraction,
    multiply each fraction by baseline_total_pps (or fallback if not yet
    calibrated).
    """
    entry = active_entry(schedule, elapsed_sec)
    if "caps_pps" in entry:
        return [int(x) for x in entry["caps_pps"]]
    if "caps_fraction" in entry:
        denom = baseline_total_pps if baseline_total_pps is not None else fallback_total_pps
        return [int(f * denom) for f in entry["caps_fraction"]]
    raise ValueError(f"schedule entry missing caps_pps or caps_fraction: {entry}")


def read_window(csv_path: Path, t_lo: int, t_hi: int) -> dict[str, list[int]]:
    """Return per-IP list of pps samples for timestamps in [t_lo, t_hi)."""
    out: dict[str, list[int]] = defaultdict(list)
    if not csv_path.exists():
        return out
    with csv_path.open() as f:
        header = f.readline()  # timestamp,ip,pps
        for line in f:
            parts = line.rstrip("\n").split(",")
            if len(parts) < 3:
                continue
            try:
                ts = int(parts[0])
                pps = int(parts[2])
            except ValueError:
                continue
            if t_lo <= ts < t_hi:
                out[parts[1]].append(pps)
    return out


def read_current_weights(strategies_dir: Path, n_backends: int
                         ) -> list[int]:
    """Read the weights the generator last installed. Returns uniform
    weights as a fallback for the first cycle / missing file / malformed
    contents — uniform is the "no evidence" prior the controller itself
    starts from."""
    path = strategies_dir / "current_weights.json"
    if not path.exists():
        return [1] * n_backends
    try:
        data = json.loads(path.read_text())
        w = [int(x) for x in data.get("weights", [])]
        if len(w) != n_backends or not any(w):
            return [1] * n_backends
        return w
    except (json.JSONDecodeError, OSError, ValueError, TypeError):
        return [1] * n_backends


def read_last_tx_rate(csv_path: Path, window_sec: int) -> float | None:
    """Average TX pps over the trailing window of tx-stats.csv, or None
    if the CSV doesn't exist yet or has no recent rows."""
    if not csv_path.exists():
        return None
    now = int(time.time())
    lo = now - window_sec
    vals: list[int] = []
    try:
        with csv_path.open() as f:
            f.readline()  # header: timestamp,pps_tx
            for line in f:
                parts = line.rstrip("\n").split(",")
                if len(parts) < 2:
                    continue
                try:
                    ts = int(parts[0])
                    pps = int(parts[1])
                except ValueError:
                    continue
                if lo <= ts <= now:
                    vals.append(pps)
    except OSError:
        return None
    return (sum(vals) / len(vals)) if vals else None


def estimate_latency_us(sent_pps: float, cap_pps: float,
                        base_us: float = 10.0,
                        saturation_us: float = 100_000.0) -> float:
    """Synthetic mean packet latency for a backend under load.

    Uses a simple M/M/1 sojourn-time model: mean latency = 1 / (μ − λ)
    where μ = service rate (cap_pps) and λ = arrival rate (sent_pps).
    Floored at `base_us` (think: fixed per-packet processing + cable)
    and clamped at `saturation_us` when the backend is at or past
    capacity — a saturated M/M/1 queue has unbounded mean latency, so
    any finite number is a convention; 100ms is well above the
    interesting convergence region and makes saturation visible on the
    plot without breaking the y-axis.
    """
    if cap_pps <= 0 or sent_pps <= 0:
        return base_us
    if sent_pps >= cap_pps:
        return saturation_us
    mean_s = 1.0 / (cap_pps - sent_pps)
    return max(base_us, min(saturation_us, mean_s * 1_000_000.0))


def simulate_sent_miss(total_inbound_pps: float,
                       weights: list[int],
                       caps_pps: list[int],
                       window_sec: float
                       ) -> list[tuple[int, int, float]]:
    """Given the currently-installed weights and synthetic caps, compute
    the per-backend (sent, miss, latency_us) tuple for this window.
    Traffic is allocated proportionally to weights; miss is the strict
    overflow above each backend's cap; latency is the M/M/1 mean sojourn
    time at the current sent/cap utilization."""
    total_w = sum(weights) or 1
    out: list[tuple[int, int, float]] = []
    for w, cap in zip(weights, caps_pps):
        sent_pps = total_inbound_pps * w / total_w
        miss_pps = max(0.0, sent_pps - cap) if cap > 0 else 0.0
        lat_us = estimate_latency_us(sent_pps, float(cap))
        out.append((int(sent_pps * window_sec),
                    int(miss_pps * window_sec),
                    lat_us))
    return out


def build_snapshot(
    *,
    timestamp_sec: int,
    window_sec: float,
    backend_ips: list[str],
    window_samples: dict[str, list[int]],
    caps_pps: list[int],
) -> dict:
    """Fold the collector's per-second pps into 5-second-window
    sent/missed counters the generator expects."""
    backends = []
    for idx, ip in enumerate(backend_ips):
        samples = window_samples.get(ip, [])
        avg_pps = sum(samples) / len(samples) if samples else 0.0
        cap = caps_pps[idx] if idx < len(caps_pps) else 0
        sent = int(avg_pps * window_sec)
        overflow_pps = max(0.0, avg_pps - cap) if cap > 0 else 0.0
        missed = int(overflow_pps * window_sec)
        backends.append(
            {
                "idx": idx,
                "ip": ip,
                "packets_sent": sent,
                "packets_missed": missed,
                "active_connections": 0,
                "capacity_hint": int(cap),
            }
        )
    return {
        "timestamp": timestamp_sec,
        "window_sec": window_sec,
        "backends": backends,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traffic-csv", required=True, type=Path,
                    help="collector's traffic-stats.csv (grows over time)")
    ap.add_argument("--config", required=True, type=Path,
                    help="ALB config yaml (used only to extract backend IP list)")
    ap.add_argument("--caps-schedule", required=True, type=Path,
                    help="JSON: [{t_offset_sec, caps_pps: [..]}, ...]")
    ap.add_argument("--start-time", required=True, type=int,
                    help="unix timestamp taken as t=0 for the schedule")
    ap.add_argument("--out", required=True, type=Path,
                    help="write this path atomically each cycle")
    ap.add_argument("--history", type=Path, default=None,
                    help="optional: append every emitted snapshot here (JSON lines)")
    ap.add_argument("--window", type=float, default=5.0,
                    help="window seconds to average over (default 5)")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="emit cadence in seconds (default 5)")
    ap.add_argument("--baseline-min-pps", type=float, default=100_000.0,
                    help="minimum observed total pps before latching the "
                         "baseline used for caps_fraction (default 100k)")
    ap.add_argument("--fallback-total-pps", type=float, default=1_000_000.0,
                    help="total pps to use for caps_fraction when baseline "
                         "is not yet calibrated (default 1M)")
    ap.add_argument("--baseline-file", type=Path, default=None,
                    help="write the latched baseline total pps here so the "
                         "plotter can resolve caps_fraction after the run")
    ap.add_argument("--simulate", action="store_true",
                    help="bypass the real traffic-stats.csv feedback signal. "
                         "instead, simulate per-backend sent = total * w[i]/sum(w) "
                         "and miss = max(0, sent - cap). lets us validate the "
                         "controller's algorithm end-to-end — including the real "
                         "hot-swap path — without being confounded by real-pipeline "
                         "noise (generator overload, NIC drops, etc.).")
    ap.add_argument("--strategies-dir", type=Path, default=None,
                    help="required in --simulate mode: dir where the generator "
                         "writes current_weights.json")
    ap.add_argument("--simulate-rate-pps", type=float, default=None,
                    help="total inbound pps for the simulation. if unset, "
                         "falls back to the tx-stats.csv rolling average, "
                         "else 3e6.")
    ap.add_argument("--tx-csv", type=Path, default=None,
                    help="tx-stats.csv path (--simulate uses this for rate)")
    args = ap.parse_args()

    backend_ips = read_backend_ips(args.config)
    if not backend_ips:
        print(f"no backends in {args.config}", file=sys.stderr)
        return 1
    print(f"adapter: backends={backend_ips}", file=sys.stderr)

    schedule = load_schedule(args.caps_schedule)
    print(f"adapter: schedule phases={len(schedule)}", file=sys.stderr)

    if args.simulate and args.strategies_dir is None:
        print("--simulate requires --strategies-dir", file=sys.stderr)
        return 2

    # in --simulate mode we pin the baseline up-front to the simulated
    # total inbound rate. the cap schedule's fractions multiply against
    # it, so a schedule of [0.333, 0.333, 0.333] gives each backend a
    # cap of rate/3 — at which point an equal-weight split sits exactly
    # at capacity and any weight imbalance produces visible miss.
    baseline_total_pps: float | None = None
    if args.simulate and args.simulate_rate_pps is not None:
        baseline_total_pps = float(args.simulate_rate_pps)
        if args.baseline_file is not None:
            args.baseline_file.write_text(f"{baseline_total_pps:.0f}\n")
        print(f"adapter: simulate mode, baseline pinned to "
              f"{baseline_total_pps:,.0f} pps", file=sys.stderr)

    tick = 0
    try:
        while True:
            now = int(time.time())
            elapsed = now - args.start_time

            if args.simulate:
                # simulate mode — feedback signal is synthesized from
                # current_weights × total_rate, not read from the NIC.
                if baseline_total_pps is None:
                    rate = None
                    if args.tx_csv is not None:
                        rate = read_last_tx_rate(args.tx_csv, int(args.window))
                    if rate is None or rate < args.baseline_min_pps:
                        rate = 3_000_000.0  # last-ditch default
                    baseline_total_pps = rate
                    if args.baseline_file is not None:
                        args.baseline_file.write_text(
                            f"{baseline_total_pps:.0f}\n")
                    print(f"adapter: simulate mode, baseline calibrated to "
                          f"{baseline_total_pps:,.0f} pps at t+{elapsed}s",
                          file=sys.stderr)

                weights = read_current_weights(args.strategies_dir,
                                               len(backend_ips))
                caps = caps_at(schedule, elapsed,
                               baseline_total_pps, args.fallback_total_pps)
                sim = simulate_sent_miss(baseline_total_pps, weights,
                                         caps, args.window)
                snap = {
                    "timestamp": now,
                    "window_sec": args.window,
                    "weights": weights,
                    "total_inbound_pps": int(baseline_total_pps),
                    "backends": [
                        {
                            "idx": idx,
                            "ip": backend_ips[idx],
                            "packets_sent": sent,
                            "packets_missed": miss,
                            "active_connections": 0,
                            "capacity_hint": int(caps[idx]),
                            # simulated per-backend mean packet latency.
                            # not in the generator's prompt schema (the
                            # generator doesn't consume latency) — but
                            # the plot reads it from snapshots.jsonl.
                            "latency_us": round(lat_us, 2),
                        }
                        for idx, (sent, miss, lat_us) in enumerate(sim)
                    ],
                }
            else:
                # real mode — trailing-window averages from traffic-stats.csv.
                t_hi = now
                t_lo = now - int(args.window)
                samples = read_window(args.traffic_csv, t_lo, t_hi)

                if baseline_total_pps is None:
                    per_ip_avg = {
                        ip: (sum(samples.get(ip, [])) / len(samples[ip]))
                        for ip in backend_ips if samples.get(ip)
                    }
                    total_now = sum(per_ip_avg.values())
                    if total_now >= args.baseline_min_pps:
                        baseline_total_pps = total_now
                        print(f"adapter: baseline calibrated to "
                              f"{baseline_total_pps:,.0f} pps at t+{elapsed}s",
                              file=sys.stderr)
                        if args.baseline_file is not None:
                            args.baseline_file.write_text(
                                f"{baseline_total_pps:.0f}\n")

                caps = caps_at(schedule, elapsed,
                               baseline_total_pps, args.fallback_total_pps)
                snap = build_snapshot(
                    timestamp_sec=now,
                    window_sec=args.window,
                    backend_ips=backend_ips,
                    window_samples=samples,
                    caps_pps=caps,
                )

            tmp = args.out.with_suffix(args.out.suffix + ".tmp")
            tmp.write_text(json.dumps(snap))
            tmp.replace(args.out)

            if args.history is not None:
                with args.history.open("a") as hf:
                    hf.write(json.dumps({
                        "t": now, "elapsed": elapsed, **snap,
                    }) + "\n")

            tick += 1
            if tick % 6 == 1:  # every ~30s, log a heartbeat
                line = " ".join(
                    f"{b['ip']}=sent{b['packets_sent']}/miss{b['packets_missed']}/cap{b['capacity_hint']}"
                    for b in snap["backends"]
                )
                print(f"adapter: t+{elapsed}s  {line}", file=sys.stderr)

            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
