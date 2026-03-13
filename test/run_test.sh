#!/bin/bash
# Test script for ALB with tap devices
# Usage: sudo ./test/run_test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ALB_BIN="$PROJECT_DIR/bazel-bin/src/alb"
CONFIG_FILE="$PROJECT_DIR/config/config.yaml"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

if [ ! -f "$ALB_BIN" ]; then
    echo "ALB binary not found. Building with bazel..."
    bazel build //src:alb
fi

echo "=== ALB Test with TAP Devices ==="
echo ""
echo "This will:"
echo "  1. Start ALB listening for UDP on port 5678"
echo "  2. Send UDP packets to dtap0 with dst_port=5678"
echo "  3. Receive rewritten packets on dtap1"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    # Kill ALB if running
    if [ -n "$ALB_PID" ] && kill -0 "$ALB_PID" 2>/dev/null; then
        echo "Stopping ALB (PID $ALB_PID)..."
        kill "$ALB_PID" 2>/dev/null || true
        wait "$ALB_PID" 2>/dev/null || true
    fi
    # Tap devices are auto-removed when DPDK exits
    echo "Done."
}
trap cleanup EXIT

LISTEN_PORT=5678

# Start ALB with tap devices
echo "=== Starting ALB ==="
cd "$PROJECT_DIR"
"$ALB_BIN" -l 0 \
    --vdev=net_tap0,iface=dtap0 \
    --vdev=net_tap1,iface=dtap1 \
    --no-telemetry \
    -- "$CONFIG_FILE" "$LISTEN_PORT" \
    2>&1 &
ALB_PID=$!

echo "ALB started with PID $ALB_PID"
echo "Waiting for tap interfaces to be ready..."
sleep 3

# Check if tap interfaces exist
if ! ip link show dtap0 &>/dev/null; then
    echo "ERROR: dtap0 interface not created"
    exit 1
fi
if ! ip link show dtap1 &>/dev/null; then
    echo "ERROR: dtap1 interface not created"
    exit 1
fi

# Bring up tap interfaces
echo "Configuring tap interfaces..."
ip link set dtap0 up
ip link set dtap1 up

echo ""
echo "=== Tap Interfaces ==="
ip link show dtap0
ip link show dtap1
echo ""

# Send test packets and verify round-robin
echo "=== Sending Test Packets ==="
python3 "$SCRIPT_DIR/send_udp.py" \
    --tx-iface dtap0 \
    --rx-iface dtap1 \
    --dst-ip 192.168.1.1 \
    --dst-port 5678 \
    --count 6 \
    --interval 0.2 \
    --verify-round-robin \
    --expected-backends 192.168.1.100 192.168.1.101 192.168.1.102

echo ""
echo "=== Test Complete ==="
