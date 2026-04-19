#!/bin/bash
# End-to-end 4-port loopback test for the ALB.
#
# Topology:
#   [traffic-generator]  P1 --cable--> P2  [ALB]  P3 --cable--> P4  [XDP collector]
#
# Defaults assume the four-port Mellanox-like NIC described in this tree:
#   P1 = enp4s0f0np0 (TX)              -> DPDK (vfio-pci)
#   P2 = enp4s0f1np1 (ALB ingress)     -> DPDK (vfio-pci)
#   P3 = enp4s0f2np2 (ALB egress)      -> DPDK (vfio-pci)
#   P4 = enp4s0f3np3 (XDP sink)        -> kernel
#
# Outputs (in $OUTDIR, default test/results/<timestamp>):
#   tx-stats.csv           -> input metric (generator TX pps, per second)
#   traffic-stats.csv      -> output metric (XDP packets_delta per backend IP)
#   alb.log, gen.log, col.log
#
# Usage: sudo ./test/run_4port_test.sh [duration_seconds]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

DURATION="${1:-30}"

P1="${P1:-enp4s0f0np0}"  # generator TX
P2="${P2:-enp4s0f1np1}"  # ALB ingress (DPDK)
P3="${P3:-enp4s0f2np2}"  # ALB egress  (DPDK)
P4="${P4:-enp4s0f3np3}"  # XDP collector sink (kernel)

OUTDIR="${OUTDIR:-$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)}"

ALB_BIN="$PROJECT_DIR/bazel-bin/src/alb"
GEN_BIN="$PROJECT_DIR/bazel-bin/packages/traffic-generator/traffic-generator"
COL_BIN="$PROJECT_DIR/bazel-bin/packages/traffic-collector/traffic-collector"
CONFIG_FILE="$SCRIPT_DIR/config-4port.yaml"
LISTEN_PORT=5678

if [ "$EUID" -ne 0 ]; then
    echo "Must run as root (sudo)" >&2
    exit 1
fi

for bin in "$ALB_BIN" "$GEN_BIN" "$COL_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "Missing binary: $bin" >&2
        echo "Run: bazel build //src:alb //packages/traffic-generator:traffic-generator //packages/traffic-collector:traffic-collector" >&2
        exit 1
    fi
done

mkdir -p "$OUTDIR"
echo "Results: $OUTDIR"

# --- hugepages ------------------------------------------------------------
if [ "$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)" -lt 1024 ]; then
    echo "Reserving 1024 x 2M hugepages..."
    echo 1024 > /proc/sys/vm/nr_hugepages
fi

# --- bind P1/P2/P3 to vfio-pci, keep P4 on kernel -------------------------
echo "Binding $P1 $P2 $P3 to vfio-pci..."
mapfile -t PCIS < <("$SCRIPT_DIR/bind_ports.sh" "$P1" "$P2" "$P3")
PCI_P1="${PCIS[0]}"
PCI_P2="${PCIS[1]}"
PCI_P3="${PCIS[2]}"
echo "  $P1 -> $PCI_P1"
echo "  $P2 -> $PCI_P2"
echo "  $P3 -> $PCI_P3"

# Bring up P4 for the XDP collector
ip link set "$P4" up

# Snapshot P4 rx counters so we can see if frames physically reach it,
# independent of whether XDP counts them.
P4_RX_BEFORE=$(ethtool -S "$P4" | awk '/\yrx_packets:/ {print $2; exit}')
echo "P4 rx_packets before: ${P4_RX_BEFORE:-?}"

# --- cleanup trap ---------------------------------------------------------
ALB_PID=""
GEN_PID=""
COL_PID=""
cleanup() {
    echo ""
    echo "=== Cleanup ==="
    for pid in "$GEN_PID" "$ALB_PID" "$COL_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$GEN_PID" "$ALB_PID" "$COL_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    echo "Restoring kernel drivers on $P1 $P2 $P3..."
    "$SCRIPT_DIR/unbind_ports.sh" "$PCI_P1" "$PCI_P2" "$PCI_P3" || true
}
trap cleanup EXIT INT TERM

# --- start XDP collector on P4 -------------------------------------------
echo "Starting traffic-collector on $P4..."
(
    cd "$OUTDIR"
    # traffic-collector writes ./traffic-stats.csv in its cwd
    "$COL_BIN" "$P4" > "$OUTDIR/col.log" 2>&1
) &
COL_PID=$!
sleep 1
if ! kill -0 "$COL_PID" 2>/dev/null; then
    echo "traffic-collector failed to start:" >&2
    cat "$OUTDIR/col.log" >&2
    exit 1
fi

# --- start ALB on P2 (ingress) + P3 (egress) ------------------------------
# DPDK port index 0 = first -a arg = P2, port 1 = P3. ALB's worker TXes on
# (port ^ 1), so ingress P2 -> egress P3 and vice versa.
echo "Starting ALB on $PCI_P2 (ingress) + $PCI_P3 (egress)..."
# Pin ALB to distinct physical cores (0..5 on this 8-core+HT box):
#   0 = main (stats), 1 = manager (hot-reload watcher),
#   2..5 = 4 forwarding workers, one per RX/TX queue (RSS across queues).
"$ALB_BIN" -l 0,1,2,3,4,5 \
    -a "$PCI_P2" -a "$PCI_P3" \
    --file-prefix=alb \
    -- "$CONFIG_FILE" "$LISTEN_PORT" \
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
# Generator needs more than one TX worker to push past ~1.4 Mpps. Layout:
#   lcore 6  -> main/stats       (phys 6)
#   lcore 7  -> TX worker        (phys 7, dedicated)
#   lcore 8  -> TX worker        (HT sibling of phys 0, shares with ALB main
#                                 which only wakes ~1/s for stats)
#   lcore 9  -> TX worker        (HT sibling of phys 1, shares with ALB
#                                 manager which is blocked on epoll)
#   lcore 14 -> TX worker        (HT sibling of phys 6, shares with gen's
#                                 own main which sleeps 1s/s)
#   lcore 15 -> RX drain         (HT sibling of phys 7, shares with TX
#                                 worker on 7; drain is cheap, acceptable)
# ALB workers on phys cores 2..5 and their HT siblings (10..13) are
# deliberately left alone so ALB forwarding isn't starved.
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
kill -INT "$COL_PID" 2>/dev/null || true
wait "$GEN_PID" 2>/dev/null || true
wait "$ALB_PID" 2>/dev/null || true
wait "$COL_PID" 2>/dev/null || true
GEN_PID=""
ALB_PID=""
COL_PID=""

P4_RX_AFTER=$(ethtool -S "$P4" | awk '/\yrx_packets:/ {print $2; exit}')
P4_RX_DELTA=$(( ${P4_RX_AFTER:-0} - ${P4_RX_BEFORE:-0} ))
echo "P4 rx_packets after:  ${P4_RX_AFTER:-?}  (delta ${P4_RX_DELTA})"
echo "$P4_RX_BEFORE $P4_RX_AFTER $P4_RX_DELTA" > "$OUTDIR/p4-ethtool.txt"

# Move the collector's default-named output into place if it landed in OUTDIR
if [ -f "$OUTDIR/traffic-stats.csv" ]; then
    echo "Output: $OUTDIR/traffic-stats.csv"
fi
if [ -f "$OUTDIR/tx-stats.csv" ]; then
    echo "Input:  $OUTDIR/tx-stats.csv"
fi

echo ""
echo "=== Done ==="
echo "Plot with: python3 $SCRIPT_DIR/plot_metrics.py $OUTDIR"
