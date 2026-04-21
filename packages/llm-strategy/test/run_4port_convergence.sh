#!/usr/bin/env bash
# End-to-end LLM convergence test against a REAL running ALB.
#
# Topology: identical to test/run_4port_test.sh —
#   [traffic-generator]  P1 --cable--> P2  [ALB]  P3 --cable--> P4  [XDP collector]
#
# Pipeline additions vs. run_4port_test.sh:
#   - installs libweightedstrategy.so into ./strategies/libstrategy.so at start
#     so ALB begins routing by weight (all weights=1 via config = equal split).
#   - runs metrics_adapter.py in a loop: reads the collector's traffic-stats.csv,
#     applies a synthetic per-backend capacity schedule, writes a snapshot.json
#     in the MetricsSnapshot format the generator consumes.
#   - runs packages/llm-strategy:generator (stub mode by default; set
#     ANTHROPIC_API_KEY to use the LLM path) which polls snapshot.json,
#     rewrites libstrategy.so, and the ALB's inotify watcher hot-swaps it.
#   - after the run, plots observed per-backend throughput against the
#     capacity schedule (real convergence graph, not simulator).
#
# Requires: sudo, vfio-pci kmod loaded, P4 kernel-bound, DPDK hugepages.
# Usage:    sudo ./packages/llm-strategy/test/run_4port_convergence.sh [DURATION]
#
# Environment knobs (same naming as run_4port_test.sh where they overlap):
#   P1..P4                 port names (defaults match the Mellanox box in-tree)
#   OUTDIR                 results dir (default test/results/<timestamp>-conv)
#   SCHEDULE               capacity schedule JSON (default: caps_schedule_default.json)
#   ANTHROPIC_API_KEY      if set, generator uses Claude; otherwise stub
#   MODEL                  claude-haiku-4-5 by default
#   GEN_INTERVAL           generator poll interval (default 5 sec)
#   ADAPTER_WINDOW         adapter's averaging window (default 5 sec)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_DIR"

DURATION="${1:-210}"

P1="${P1:-enp4s0f0np0}"
P2="${P2:-enp4s0f1np1}"
P3="${P3:-enp4s0f2np2}"
P4="${P4:-enp4s0f3np3}"

OUTDIR="${OUTDIR:-$PROJECT_DIR/test/results/$(date +%Y%m%d-%H%M%S)-conv}"
SCHEDULE="${SCHEDULE:-$SCRIPT_DIR/caps_schedule_default.json}"
MODEL="${MODEL:-claude-haiku-4-5}"
GEN_INTERVAL="${GEN_INTERVAL:-5}"
ADAPTER_WINDOW="${ADAPTER_WINDOW:-5}"
# simulate=1 (default): adapter bypasses real traffic feedback and drives
# the controller from (current_weights × total_rate) + synthetic caps. the
# real ALB still hot-swaps .so's — we're only replacing the noisy NIC
# feedback path with a clean simulation so the convergence behavior is
# testable without traffic-generator overload skewing the data.
SIMULATE="${SIMULATE:-1}"
SIMULATE_RATE_PPS="${SIMULATE_RATE_PPS:-3000000}"

ALB_BIN="$PROJECT_DIR/bazel-bin/src/alb"
GEN_BIN="$PROJECT_DIR/bazel-bin/packages/traffic-generator/traffic-generator"
COL_BIN="$PROJECT_DIR/bazel-bin/packages/traffic-collector/traffic-collector"
LLMGEN_BIN="$PROJECT_DIR/bazel-bin/packages/llm-strategy/generator"
SMOKE_BIN="$PROJECT_DIR/bazel-bin/packages/llm-strategy/smoke_tester"
INITIAL_SO="$PROJECT_DIR/bazel-bin/packages/balancer-strategies/libweightedstrategy.so"
CONFIG_FILE="$PROJECT_DIR/test/config-4port.yaml"
INCLUDE_DIR="$PROJECT_DIR/packages/balancer-strategies/include"
STRATEGIES_DIR="$PROJECT_DIR/strategies"
LISTEN_PORT=5678

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root (sudo)" >&2
    exit 1
fi

for bin in "$ALB_BIN" "$GEN_BIN" "$COL_BIN" "$LLMGEN_BIN" "$SMOKE_BIN" "$INITIAL_SO"; do
    if [ ! -e "$bin" ]; then
        echo "Missing: $bin" >&2
        echo "Build with:" >&2
        echo "  bazel build //src:alb \\" >&2
        echo "              //packages/traffic-generator:traffic-generator \\" >&2
        echo "              //packages/traffic-collector:traffic-collector \\" >&2
        echo "              //packages/llm-strategy:generator \\" >&2
        echo "              //packages/llm-strategy:smoke_tester \\" >&2
        echo "              //packages/balancer-strategies:libweightedstrategy.so" >&2
        exit 1
    fi
done

mkdir -p "$OUTDIR" "$STRATEGIES_DIR"
echo "Results: $OUTDIR"
cp "$SCHEDULE" "$OUTDIR/caps_schedule.json"

# --- hugepages ------------------------------------------------------------
if [ "$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)" -lt 1024 ]; then
    echo "Reserving 1024 x 2M hugepages..."
    echo 1024 > /proc/sys/vm/nr_hugepages
fi

# --- bind P1/P2/P3 --------------------------------------------------------
echo "Binding $P1 $P2 $P3 to vfio-pci..."
mapfile -t PCIS < <("$PROJECT_DIR/test/bind_ports.sh" "$P1" "$P2" "$P3")
PCI_P1="${PCIS[0]}"
PCI_P2="${PCIS[1]}"
PCI_P3="${PCIS[2]}"
ip link set "$P4" up

# --- install initial strategy --------------------------------------------
# Start with libweightedstrategy.so so ALB boots with a dlopen'd strategy
# from the start — avoids a transient where the fallback round-robin runs
# before the generator writes its first .so.
cp "$INITIAL_SO" "$STRATEGIES_DIR/.libstrategy.so.tmp"
mv  "$STRATEGIES_DIR/.libstrategy.so.tmp" "$STRATEGIES_DIR/libstrategy.so"
echo "Installed initial libstrategy.so (weighted, uniform weights from config)"

# --- cleanup trap ---------------------------------------------------------
ALB_PID=""
GEN_PID=""
COL_PID=""
ADAPTER_PID=""
LLM_PID=""

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for pid in "$LLM_PID" "$ADAPTER_PID" "$GEN_PID" "$ALB_PID" "$COL_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$LLM_PID" "$ADAPTER_PID" "$GEN_PID" "$ALB_PID" "$COL_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    echo "Restoring kernel drivers on $P1 $P2 $P3..."
    "$PROJECT_DIR/test/unbind_ports.sh" "$PCI_P1" "$PCI_P2" "$PCI_P3" || true
}
trap cleanup EXIT INT TERM

# --- start collector on P4 -----------------------------------------------
echo "Starting traffic-collector on $P4..."
(
    cd "$OUTDIR"
    "$COL_BIN" "$P4" > "$OUTDIR/col.log" 2>&1
) &
COL_PID=$!
sleep 1
if ! kill -0 "$COL_PID" 2>/dev/null; then
    echo "collector failed to start:" >&2; cat "$OUTDIR/col.log" >&2; exit 1
fi

# --- start ALB on P2 + P3 ------------------------------------------------
echo "Starting ALB on $PCI_P2 (ingress) + $PCI_P3 (egress)..."
"$ALB_BIN" -l 0,1,2,3,4,5 \
    -a "$PCI_P2" -a "$PCI_P3" \
    --file-prefix=alb \
    -- "$CONFIG_FILE" "$LISTEN_PORT" \
    > "$OUTDIR/alb.log" 2>&1 &
ALB_PID=$!
sleep 3
if ! kill -0 "$ALB_PID" 2>/dev/null; then
    echo "ALB failed to start:" >&2; cat "$OUTDIR/alb.log" >&2; exit 1
fi

# --- start adapter -------------------------------------------------------
# record start-time so the schedule's t_offset_sec aligns with wall time.
START_TIME="$(date +%s)"
echo "$START_TIME" > "$OUTDIR/start_time.txt"
echo "Starting metrics_adapter (start_time=$START_TIME)..."
ADAPTER_ARGS=(
    --traffic-csv   "$OUTDIR/traffic-stats.csv"
    --config        "$CONFIG_FILE"
    --caps-schedule "$OUTDIR/caps_schedule.json"
    --start-time    "$START_TIME"
    --out           "$OUTDIR/snapshot.json"
    --history       "$OUTDIR/snapshots.jsonl"
    --window        "$ADAPTER_WINDOW"
    --interval      "$GEN_INTERVAL"
    --baseline-file "$OUTDIR/baseline_pps.txt"
)
if [ "$SIMULATE" = "1" ]; then
    ADAPTER_ARGS+=(
        --simulate
        --strategies-dir    "$STRATEGIES_DIR"
        --simulate-rate-pps "$SIMULATE_RATE_PPS"
        --tx-csv            "$OUTDIR/tx-stats.csv"
    )
    echo "Adapter: SIMULATE mode (rate=${SIMULATE_RATE_PPS} pps)"
else
    echo "Adapter: REAL mode (feedback from traffic-stats.csv)"
fi
python3 "$SCRIPT_DIR/metrics_adapter.py" "${ADAPTER_ARGS[@]}" \
    > "$OUTDIR/adapter.log" 2>&1 &
ADAPTER_PID=$!
sleep 1
if ! kill -0 "$ADAPTER_PID" 2>/dev/null; then
    echo "adapter failed to start:" >&2; cat "$OUTDIR/adapter.log" >&2; exit 1
fi

# --- start LLM generator -------------------------------------------------
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    # running as root under sudo — check the python root will actually
    # see has anthropic installed, otherwise the generator spams a
    # fallback line every cycle.
    if ! python3 -c "import anthropic" 2>/dev/null; then
        echo "WARNING: ANTHROPIC_API_KEY is set but root's python3 can't" >&2
        echo "         import 'anthropic'. Install with:" >&2
        echo "           sudo pip install --break-system-packages anthropic" >&2
        echo "         Falling back to --stub for this run." >&2
        STUB_FLAG="--stub"
    else
        echo "Starting LLM generator (model=$MODEL)..."
        STUB_FLAG=""
    fi
else
    echo "ANTHROPIC_API_KEY unset — starting generator in stub mode."
    STUB_FLAG="--stub"
fi
"$LLMGEN_BIN" \
    --feed            "$OUTDIR/snapshot.json" \
    --strategies-dir  "$STRATEGIES_DIR" \
    --include-dir     "$INCLUDE_DIR" \
    --smoke-bin       "$SMOKE_BIN" \
    --model           "$MODEL" \
    --interval        "$GEN_INTERVAL" \
    --latency-log     "$OUTDIR/latency.jsonl" \
    $STUB_FLAG \
    > "$OUTDIR/llmgen.log" 2>&1 &
LLM_PID=$!
sleep 1
if ! kill -0 "$LLM_PID" 2>/dev/null; then
    echo "llm-generator failed to start:" >&2; cat "$OUTDIR/llmgen.log" >&2; exit 1
fi

# --- start traffic generator ---------------------------------------------
echo "Starting traffic-generator on $PCI_P1..."
"$GEN_BIN" -l 6,7,8,9,14,15 \
    -a "$PCI_P1" \
    --file-prefix=gen \
    -- "$OUTDIR/tx-stats.csv" \
    > "$OUTDIR/gen.log" 2>&1 &
GEN_PID=$!
sleep 2
if ! kill -0 "$GEN_PID" 2>/dev/null; then
    echo "gen failed to start:" >&2; cat "$OUTDIR/gen.log" >&2; exit 1
fi

# --- run ------------------------------------------------------------------
echo ""
echo "=== Running for ${DURATION}s ==="
echo "Ctrl+C to stop early."
sleep "$DURATION"

echo ""
echo "=== Stopping ==="
kill -INT "$GEN_PID"     2>/dev/null || true
kill -INT "$LLM_PID"     2>/dev/null || true
kill -INT "$ADAPTER_PID" 2>/dev/null || true
kill -INT "$ALB_PID"     2>/dev/null || true
kill -INT "$COL_PID"     2>/dev/null || true
wait "$GEN_PID" 2>/dev/null || true
wait "$LLM_PID" 2>/dev/null || true
wait "$ADAPTER_PID" 2>/dev/null || true
wait "$ALB_PID" 2>/dev/null || true
wait "$COL_PID" 2>/dev/null || true
GEN_PID=""; LLM_PID=""; ADAPTER_PID=""; ALB_PID=""; COL_PID=""

echo ""
echo "=== Plot ==="
python3 "$SCRIPT_DIR/plot_4port_convergence.py" "$OUTDIR" || true
python3 "$SCRIPT_DIR/plot_latency.py"           "$OUTDIR" || true
python3 "$SCRIPT_DIR/plot_cycle_latency.py"     "$OUTDIR" || true

echo ""
echo "=== Done ==="
echo "Outputs in: $OUTDIR"
echo "  traffic-stats.csv    — observed per-backend pps (from XDP collector)"
echo "  tx-stats.csv         — total TX pps (from traffic-generator)"
echo "  caps_schedule.json   — applied capacity schedule"
echo "  snapshot.json        — last snapshot fed to the LLM generator"
echo "  snapshots.jsonl      — full adapter history (one JSON per cycle)"
echo "  llmgen.log           — generator cycle log (which attempts succeeded)"
echo "  latency.jsonl        — per-cycle latency breakdown (JSON lines)"
echo "  adapter.log          — adapter heartbeats (includes baseline calibration)"
echo "  alb.log, gen.log, col.log"
echo "  convergence-real.png — per-backend observed vs synthetic capacity"
echo "  latency-real.png     — per-backend packet latency over time (M/M/1 model)"
echo "  cycle-latency.png    — controller cycle latency (compile+smoke+LLM)"
