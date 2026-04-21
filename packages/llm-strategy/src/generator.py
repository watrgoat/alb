#!/usr/bin/env python3
"""LLM-driven load balancer strategy generator.

Reads metrics snapshots from a JSON feed (file path or stdin), asks Claude
to write a new Strategy implementation, compiles it to a shared object,
smoke-tests it in a subprocess, and atomically installs to
./strategies/libstrategy.so so the ALB's inotify watcher picks it up.

Without ANTHROPIC_API_KEY, falls back to a deterministic stub that emits a
weighted strategy whose weights track each backend's estimated capacity.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_MODEL = "claude-haiku-4-5"

SYSTEM_PROMPT = """You write C++ load-balancer strategies.

Return one self-contained C++ source file implementing the Strategy ABI below.
No markdown fences, no explanation, no prose. Source only.

Hard constraints:
- Include only <cstdint>. No <iostream>, no <thread>, no syscalls, no globals
  with non-trivial destructors.
- Implement a class deriving from Strategy with a non-virtual select() that
  returns a pointer inside the servers array passed to create_strategy.
- Export `extern "C" Strategy *create_strategy(ServerState *, int)` and
  `extern "C" void destroy_strategy(Strategy *)`.
- Do not allocate shared state outside the Strategy instance. Do not call
  exit(). Do not loop unboundedly inside select().

Objective: minimize sum(packets_missed) across backends while keeping total
throughput within 5% of current. Use per-backend capacity_hint and recent
miss rates to bias routing. Dispatch by `packet_hash % total_weight` is a
safe pattern; `active_connections` can weight it further.
"""

ABI_MARKER = "// === Strategy ABI ===\n"


def load_abi(strategy_hdr: Path) -> str:
    return ABI_MARKER + strategy_hdr.read_text()


def build_user_prompt(
    abi: str,
    snapshot: dict,
    history: list[dict],
) -> str:
    hist_blocks = []
    for h in history[-3:]:
        hist_blocks.append(
            f"--- attempt {h['attempt']} (miss_rate={h['miss_rate']:.3f}) ---\n"
            f"{h['summary']}\n"
        )
    hist = "\n".join(hist_blocks) if hist_blocks else "(none yet)"
    return (
        f"{abi}\n"
        "// === latest metrics snapshot ===\n"
        f"{json.dumps(snapshot, indent=2)}\n\n"
        "// === recent attempts (most recent last) ===\n"
        f"{hist}\n\n"
        "Write the new Strategy source file now."
    )


def call_claude(system: str, user: str, model: str) -> str:
    import anthropic  # type: ignore

    client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=4096,
        system=[
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user}],
    )
    return "".join(
        block.text for block in resp.content if getattr(block, "type", "") == "text"
    )


def strip_fences(src: str) -> str:
    # Claude occasionally wraps despite the system prompt; be tolerant.
    s = src.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if s.endswith("```"):
            s = s[: -3]
        elif "```" in s:
            s = s.rsplit("```", 1)[0]
    return s.strip()


def stub_weights(cap_est: list[float], snap: dict) -> tuple[list[int], list[float]]:
    backends = snap["backends"]
    n = len(backends)
    if len(cap_est) != n:
        cap_est = [1.0] * n
    new_cap = list(cap_est)
    for i, b in enumerate(backends):
        sent = float(b["packets_sent"])
        miss = float(b["packets_missed"])
        if miss > 0:
            new_cap[i] = max(1.0, sent - miss)
        else:
            new_cap[i] = max(1.0, sent * 1.2)
    weights = [max(1, int(round(v))) for v in new_cap]
    return weights, new_cap


def emit_stub_source(weights: list[int]) -> str:
    arr = ",".join(f"{w}u" for w in weights)
    n = len(weights)
    return f"""#include "strategy.hpp"
namespace {{
constexpr uint32_t kWeights[] = {{{arr}}};
constexpr int kCount = {n};
class GenStrategy : public Strategy {{
  ServerState *servers_;
  int count_;
  uint32_t total_;
 public:
  GenStrategy(ServerState *s, int n) : servers_(s), count_(n), total_(0) {{
    for (int i = 0; i < n && i < kCount; i++) total_ += kWeights[i];
    if (!total_) total_ = 1;
  }}
  ServerState *select(const StrategyInput &in) override {{
    uint32_t t = in.packet_hash % total_;
    uint32_t c = 0;
    for (int i = 0; i < count_ && i < kCount; i++) {{
      c += kWeights[i];
      if (t < c) return &servers_[i];
    }}
    return &servers_[count_ - 1];
  }}
}};
}}
extern "C" Strategy *create_strategy(ServerState *s, int n) {{
  return new GenStrategy(s, n);
}}
extern "C" void destroy_strategy(Strategy *s) {{ delete s; }}
"""


def compile_so(src_path: Path, out_so: Path, include_dir: Path) -> subprocess.CompletedProcess:
    cmd = [
        "g++",
        "-fPIC",
        "-shared",
        "-O2",
        "-std=c++17",
        f"-I{include_dir}",
        str(src_path),
        "-o",
        str(out_so),
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def smoke_test(smoke_bin: Path, so_path: Path, timeout: float = 10.0) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            [str(smoke_bin), str(so_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, "smoke test timed out"
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def atomic_install(src_so: Path, strategies_dir: Path):
    strategies_dir.mkdir(parents=True, exist_ok=True)
    tmp = strategies_dir / ".libstrategy.so.tmp"
    shutil.copy2(src_so, tmp)
    os.rename(tmp, strategies_dir / "libstrategy.so")


def load_snapshot(feed: str) -> dict:
    if feed == "-":
        return json.loads(sys.stdin.read())
    return json.loads(Path(feed).read_text())


def miss_rate(snap: dict) -> float:
    tot = sum(b["packets_sent"] for b in snap["backends"]) or 1
    missed = sum(b["packets_missed"] for b in snap["backends"])
    return missed / tot


def run_cycle(
    cycle: int,
    snapshot: dict,
    workdir: Path,
    strategies_dir: Path,
    include_dir: Path,
    smoke_bin: Path,
    model: str,
    cap_est: list[float],
    history: list[dict],
    force_stub: bool,
) -> tuple[bool, list[float]]:
    use_llm = not force_stub and os.environ.get("ANTHROPIC_API_KEY")

    last_err = ""
    for attempt in range(1, 4):
        if use_llm:
            sys_prompt = SYSTEM_PROMPT
            if last_err:
                sys_prompt += f"\n\nPrevious attempt failed to compile:\n{last_err}\nFix it."
            try:
                source = strip_fences(
                    call_claude(
                        sys_prompt,
                        build_user_prompt(load_abi(include_dir / "strategy.hpp"), snapshot, history),
                        model,
                    )
                )
            except Exception as exc:
                print(f"[cycle {cycle}] LLM call failed ({exc}); falling back to stub",
                      file=sys.stderr)
                use_llm = False
                continue
        else:
            weights, cap_est = stub_weights(cap_est, snapshot)
            source = emit_stub_source(weights)

        src_path = workdir / f"strategy_{cycle}_{attempt}.cpp"
        so_path = workdir / f"strategy_{cycle}_{attempt}.so"
        src_path.write_text(source)
        res = compile_so(src_path, so_path, include_dir)
        if res.returncode != 0:
            last_err = res.stderr.strip()[:2000]
            print(f"[cycle {cycle} attempt {attempt}] compile failed:\n{last_err}",
                  file=sys.stderr)
            if not use_llm:
                # stub source shouldn't fail; bail out hard
                return False, cap_est
            continue

        ok, msg = smoke_test(smoke_bin, so_path)
        if not ok:
            last_err = f"smoke test failed: {msg}"
            print(f"[cycle {cycle} attempt {attempt}] {last_err}", file=sys.stderr)
            if not use_llm:
                return False, cap_est
            continue

        atomic_install(so_path, strategies_dir)
        history.append(
            {
                "attempt": cycle,
                "miss_rate": miss_rate(snapshot),
                "summary": source[:600],
            }
        )
        print(f"[cycle {cycle}] installed via attempt {attempt} "
              f"(mode={'llm' if use_llm else 'stub'})")
        return True, cap_est

    print(f"[cycle {cycle}] gave up after 3 attempts", file=sys.stderr)
    return False, cap_est


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="LLM strategy generator loop")
    ap.add_argument("--feed", default="-",
                    help="path to metrics JSON (or '-' for stdin). if "
                         "omitted, reads one snapshot from stdin and exits.")
    ap.add_argument("--strategies-dir", default="./strategies",
                    help="directory watched by manager_main")
    ap.add_argument("--include-dir", required=True,
                    help="directory containing strategy.hpp")
    ap.add_argument("--smoke-bin", required=True,
                    help="smoke tester binary path")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--stub", action="store_true",
                    help="force stub generator (no network)")
    ap.add_argument("--once", action="store_true",
                    help="read one snapshot and exit")
    ap.add_argument("--interval", type=float, default=5.0,
                    help="poll interval seconds when --feed is a file")
    return ap.parse_args()


def main():
    args = parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="llm-strategy-"))
    strategies_dir = Path(args.strategies_dir).resolve()
    include_dir = Path(args.include_dir).resolve()
    smoke_bin = Path(args.smoke_bin).resolve()

    history: list[dict] = []
    cap_est: list[float] = []
    cycle = 0
    running = [True]

    def _stop(*_):
        running[0] = False
        print("generator: interrupted, flushing and exiting", file=sys.stderr)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    last_ts = None
    while running[0]:
        cycle += 1
        try:
            snap = load_snapshot(args.feed)
        except Exception as exc:
            print(f"generator: failed to read snapshot: {exc}", file=sys.stderr)
            if args.once or args.feed == "-":
                break
            time.sleep(args.interval)
            continue
        if args.feed != "-" and snap.get("timestamp") == last_ts:
            time.sleep(args.interval)
            continue
        last_ts = snap.get("timestamp")

        ok, cap_est = run_cycle(
            cycle, snap, workdir, strategies_dir, include_dir,
            smoke_bin, args.model, cap_est, history, args.stub,
        )

        if args.once or args.feed == "-":
            sys.exit(0 if ok else 1)
        time.sleep(args.interval)

    shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
