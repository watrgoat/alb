#!/usr/bin/env python3
"""Plot controller *cycle* latency — how long each generator cycle takes
to produce and install a new .so. NOT packet latency (see plot_latency.py
for that); this is the time from one snapshot read to the next
installed strategy, broken out by phase (compile, smoke, optional LLM).

Reads latency.jsonl (emitted by generator.py --latency-log).
Output: cycle-latency.png in the same results dir.

Usage:
    python3 plot_cycle_latency.py <results_dir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def read_latency(path: Path) -> list[dict]:
    out: list[dict] = []
    if not path.exists():
        return out
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: plot_latency.py <results_dir>", file=sys.stderr)
        return 2

    d = Path(sys.argv[1])
    latency_path = d / "latency.jsonl"
    start_path = d / "start_time.txt"
    schedule_path = d / "caps_schedule.json"

    if not latency_path.exists():
        print(f"missing {latency_path} — did generator run with --latency-log?",
              file=sys.stderr)
        return 1
    if not start_path.exists():
        print(f"missing {start_path}", file=sys.stderr)
        return 1

    records = read_latency(latency_path)
    if not records:
        print(f"no records in {latency_path}", file=sys.stderr)
        return 1

    start_ts = int(start_path.read_text().strip())
    # keep only records that successfully installed — failures still get
    # logged, but the plot is about the happy-path loop cadence.
    installed = [r for r in records if r.get("status") == "installed"]
    if not installed:
        print("no installed-status records; plotting all records anyway.",
              file=sys.stderr)
        installed = records

    ts = [r["t"] - start_ts for r in installed]
    cycle = [r.get("cycle_ms", 0.0) for r in installed]
    compile_ms = [r.get("compile_ms", 0.0) for r in installed]
    smoke_ms = [r.get("smoke_ms", 0.0) for r in installed]
    llm_ms = [r.get("llm_ms", 0.0) for r in installed]
    install_overhead = [
        max(0.0, c - cm - sm - lm)
        for c, cm, sm, lm in zip(cycle, compile_ms, smoke_ms, llm_ms)
    ]

    has_llm = any(v > 0 for v in llm_ms)

    # markers: capacity-change events (same source as the convergence plot)
    markers: list[tuple[int, list]] = []
    if schedule_path.exists():
        try:
            entries = sorted(
                json.loads(schedule_path.read_text()),
                key=lambda e: e["t_offset_sec"],
            )
            markers = [
                (e["t_offset_sec"],
                 e.get("caps_pps") or e.get("caps_fraction") or [])
                for e in entries
            ]
        except (json.JSONDecodeError, KeyError):
            markers = []

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, (ax_stack, ax_total) = plt.subplots(
        2, 1, figsize=(13, 7), sharex=True,
        gridspec_kw={"height_ratios": [2, 1]},
    )

    # top: stacked breakdown of where each cycle spent its time
    labels = ["compile (g++)", "smoke (dlopen+select)"]
    ys = [compile_ms, smoke_ms]
    colors = ["#1f77b4", "#2ca02c"]
    if has_llm:
        labels.insert(0, "llm call")
        ys.insert(0, llm_ms)
        colors.insert(0, "#9467bd")
    labels.append("install + overhead")
    ys.append(install_overhead)
    colors.append("#7f7f7f")

    ax_stack.stackplot(ts, *ys, labels=labels, colors=colors, alpha=0.85)
    ax_stack.plot(ts, cycle, color="black", linewidth=1.4,
                  label="cycle total (sum)")
    ax_stack.set_ylabel("cycle time (ms)", fontsize=10)
    ax_stack.set_title(f"Generator cycle latency — {d.name}")
    ax_stack.grid(True, alpha=0.3)
    ax_stack.legend(loc="upper right", fontsize=9, ncol=2, framealpha=0.92)
    for ts_off, _ in markers:
        ax_stack.axvline(ts_off, color="grey", linestyle=":", alpha=0.6)

    # bottom: per-cycle attempt count (did we retry?)
    attempts = [r.get("attempt", 1) for r in installed]
    ax_total.step(ts, attempts, color="#d62728", where="post", linewidth=1.6,
                  label="attempts to install (>1 = retry after compile/smoke fail)")
    ax_total.set_ylabel("attempts", fontsize=10)
    ax_total.set_xlabel("seconds since start", fontsize=10)
    ax_total.set_ylim(0, max(attempts + [3]) + 0.5)
    ax_total.grid(True, alpha=0.3)
    ax_total.legend(loc="upper right", fontsize=9)
    for ts_off, _ in markers:
        ax_total.axvline(ts_off, color="grey", linestyle=":", alpha=0.6)

    fig.tight_layout()
    out = d / "cycle-latency.png"
    fig.savefig(out, dpi=120)
    print(f"wrote {out}")

    # print summary to stderr so the orchestrator's log is useful too
    p50 = sorted(cycle)[len(cycle) // 2] if cycle else 0.0
    p95 = sorted(cycle)[int(len(cycle) * 0.95)] if cycle else 0.0
    p99 = sorted(cycle)[int(len(cycle) * 0.99)] if cycle else 0.0
    print(f"cycles: {len(cycle)}  p50={p50:.0f}ms  p95={p95:.0f}ms  p99={p99:.0f}ms",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
