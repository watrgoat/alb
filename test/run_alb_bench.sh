#!/bin/bash
# ALB-only throughput bench. Generates packets at P1, lets ALB forward
# P2 -> P3, and measures at the ALB itself (via its per-port rte_eth_stats).
# No XDP collector, no P4 traffic — isolates the ALB's forwarding rate.
#
# Topology:
#   [traffic-generator]  P1 --cable--> P2  [ALB]  P3 --cable--> (dropped on wire)
#
# The point of skipping the collector is that:
#   1. The XDP path on P4 was capping observed throughput (~90%+ loss).
#   2. The ALB already reports authoritative per-second port counters
#      (ipackets, opackets, imissed) via rte_eth_stats_get. That's the
#      right measurement for "can ALB forward N Mpps?" — look at port 0
#      rx (ingress) vs port 1 tx (egress), and watch imissed for drops.
#
# Outputs (in $OUTDIR):
#   tx-stats.csv    -> generator TX pps per second        (input rate)
#   alb-stats.csv   -> port,rx_pps,tx_pps,imissed,ierrors (ALB measurement)
#   alb.log, gen.log
#
# Usage: sudo ./test/run_alb_bench.sh [duration_seconds]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

DURATION="${1:-30}"

P1="${P1:-enp4s0f0np0}"  # generator TX
P2="${P2:-enp4s0f1np1}"  # ALB ingress (DPDK)
P3="${P3:-enp4s0f2np2}"  # ALB egress  (DPDK)

OUTDIR="${OUTDIR:-$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)-albbench}"

ALB_BIN="$PROJECT_DIR/bazel-bin/src/alb"
GEN_BIN="$PROJECT_DIR/bazel-bin/packages/traffic-generator/traffic-generator"
CONFIG_FILE="$SCRIPT_DIR/config-4port.yaml"
LISTEN_PORT=5678

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root (sudo)" >&2
    exit 1
fi

for bin in "$ALB_BIN" "$GEN_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "Missing binary: $bin" >&2
        echo "Run: bazel build //src:alb //packages/traffic-generator:traffic-generator" >&2
        exit 1
    fi
done

mkdir -p "$OUTDIR"
echo "Results: $OUTDIR"

# --- hugepages ------------------------------------------------------------
# 1024 x 2M = 2 GB. Headroom for ALB's 4096-deep RX rings across 4 queues
# on 2 ports plus the generator's own pool.
if [ "$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)" -lt 1024 ]; then
    echo "Reserving 1024 x 2M hugepages..."
    echo 1024 > /proc/sys/vm/nr_hugepages
fi

# --- bind P1/P2/P3 to vfio-pci -------------------------------------------
echo "Binding $P1 $P2 $P3 to vfio-pci..."
mapfile -t PCIS < <("$SCRIPT_DIR/bind_ports.sh" "$P1" "$P2" "$P3")
PCI_P1="${PCIS[0]}"
PCI_P2="${PCIS[1]}"
PCI_P3="${PCIS[2]}"
echo "  $P1 -> $PCI_P1"
echo "  $P2 -> $PCI_P2"
echo "  $P3 -> $PCI_P3"

# --- cleanup trap ---------------------------------------------------------
ALB_PID=""
GEN_PID=""
cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for pid in "$GEN_PID" "$ALB_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$GEN_PID" "$ALB_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    echo "Restoring kernel drivers on $P1 $P2 $P3..."
    "$SCRIPT_DIR/unbind_ports.sh" "$PCI_P1" "$PCI_P2" "$PCI_P3" || true
}
trap cleanup EXIT INT TERM

# --- start ALB on P2 (ingress) + P3 (egress) ------------------------------
echo "Starting ALB on $PCI_P2 (ingress) + $PCI_P3 (egress)..."
"$ALB_BIN" -l 0,1,2,3,4,5 \
    -a "$PCI_P2" -a "$PCI_P3" \
    --file-prefix=alb \
    -- "$CONFIG_FILE" "$LISTEN_PORT" "$OUTDIR/alb-stats.csv" \
    > "$OUTDIR/alb.log" 2>&1 &
ALB_PID=$!
sleep 3
if ! kill -0 "$ALB_PID" 2>/dev/null; then
    echo "ALB failed to start:" >&2
    cat "$OUTDIR/alb.log" >&2
    exit 1
fi

# --- start traffic generator on P1 ---------------------------------------
echo "Starting traffic-generator on $PCI_P1..."
# See run_4port_test.sh for the lcore layout rationale.
"$GEN_BIN" -l 6,7,8,9,14,15 \
    -a "$PCI_P1" \
    --file-prefix=gen \
    -- "$OUTDIR/tx-stats.csv" \
    > "$OUTDIR/gen.log" 2>&1 &
GEN_PID=$!
sleep 2
if ! kill -0 "$GEN_PID" 2>/dev/null; then
    echo "traffic-generator failed to start:" >&2
    cat "$OUTDIR/gen.log" >&2
    exit 1
fi

# --- run for DURATION, then stop everything ------------------------------
echo ""
echo "=== Running for ${DURATION}s ==="
echo "Ctrl+C to stop early."
sleep "$DURATION"

echo ""
echo "=== Stopping ==="
kill -INT "$GEN_PID" 2>/dev/null || true
kill -INT "$ALB_PID" 2>/dev/null || true
wait "$GEN_PID" 2>/dev/null || true
wait "$ALB_PID" 2>/dev/null || true
GEN_PID=""
ALB_PID=""

echo ""
echo "=== Done ==="
echo "Plot with: python3 $SCRIPT_DIR/plot_metrics.py $OUTDIR"
