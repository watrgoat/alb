#!/bin/bash
# Starts the ALB with an initial strategy .so, then hot-swaps it and verifies
# that the manager lcore detects the new file and reloads without crashing.
set -e

CONFIG_FILE=$(mktemp)
STRATEGIES_DIR="./strategies"
LOG_FILE=$(mktemp)

mkdir -p "$STRATEGIES_DIR"

cat > "$CONFIG_FILE" << 'EOF'
backends:
  - ip: "192.168.1.100"
    port: 8080
    mac: "aa:bb:cc:dd:ee:ff"
EOF

cleanup() {
    kill "$ALB_PID" 2>/dev/null || true
    wait "$ALB_PID" 2>/dev/null || true
    rm -f "$CONFIG_FILE" "$LOG_FILE"
    rm -rf "$STRATEGIES_DIR" 2>/dev/null || true
}
trap cleanup EXIT

cp "$RR_LIB" "$STRATEGIES_DIR/libstrategy.so"

# 3 lcores: main (0), manager (1), worker (2)
stdbuf -o0 "$BINARY" \
    -l 0-2 \
    --no-huge \
    --no-pci \
    --no-telemetry \
    --vdev=net_null0 \
    --vdev=net_null1 \
    --file-prefix=alb_reload_test \
    --log-level=eal,info \
    -m 1024 \
    -- "$CONFIG_FILE" 5678 \
    > "$LOG_FILE" 2>&1 &
ALB_PID=$!

# wait for the manager to be watching
sleep 2

# atomically replace the strategy via rename (triggers IN_MOVED_TO)
cp "$WEIGHTED_LIB" "$STRATEGIES_DIR/libstrategy.so.tmp"
mv "$STRATEGIES_DIR/libstrategy.so.tmp" "$STRATEGIES_DIR/libstrategy.so"

sleep 1

kill "$ALB_PID" 2>/dev/null || true
wait "$ALB_PID" 2>/dev/null || true
ALB_PID=""

OUTPUT=$(cat "$LOG_FILE")

if ! echo "$OUTPUT" | grep -q "new strategy detected, reloading"; then
    echo "FAIL: reload was not triggered"
    echo "$OUTPUT"
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "reload complete"; then
    echo "FAIL: reload did not complete"
    echo "$OUTPUT"
    exit 1
fi

echo "PASS: strategy hot-swap completed successfully"
