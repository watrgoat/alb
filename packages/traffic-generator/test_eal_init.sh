#!/bin/bash
# Test that DPDK EAL initializes and ports come up with virtual devices.
set -e

OUTPUT=$(timeout 4s stdbuf -oL "$BINARY" \
    -l 0,1,2 \
    --no-huge \
    --no-pci \
    --vdev=net_null0 \
    --file-prefix=eal_init_test \
    --log-level=eal,info \
    -m 1024 \
    2>&1) || true

# Port must come up (net_null gives a MAC)
if echo "$OUTPUT" | grep -q "Port 0 MAC:"; then
    echo "PASS: EAL init and port setup succeeded"
    exit 0
fi

echo "FAIL: Port 0 did not initialize"
echo "$OUTPUT"
exit 1
