#!/bin/bash
# Test that DPDK EAL initializes and ports come up with virtual devices.
# Runs the traffic generator for a few seconds, then checks output for
# successful initialization markers.
set -e

OUTPUT=$(timeout 4s "$BINARY" \
    --vdev=net_null0 \
    --no-huge \
    --no-pci \
    --file-prefix=eal_init_test \
    --log-level=eal,info \
    -m 512 \
    -l 0,1,2 2>&1) || true

# EAL must initialize
if ! echo "$OUTPUT" | grep -q "EAL:"; then
    echo "FAIL: EAL did not produce any output"
    echo "$OUTPUT"
    exit 1
fi

# Port must come up (net_null gives a MAC)
if ! echo "$OUTPUT" | grep -q "Port 0 MAC:"; then
    echo "FAIL: Port 0 did not initialize"
    echo "$OUTPUT"
    exit 1
fi

echo "PASS: EAL init and port setup succeeded"
