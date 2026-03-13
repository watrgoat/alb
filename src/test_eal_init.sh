#!/bin/bash
# Test that DPDK EAL initializes and ports come up with virtual devices.
set -e

# Create a temporary config file for the test
CONFIG_FILE=$(mktemp)
cat > "$CONFIG_FILE" << 'EOF'
backends:
  - ip: "192.168.1.100"
    port: 8080
    mac: "aa:bb:cc:dd:ee:ff"
EOF

cleanup() {
    rm -f "$CONFIG_FILE"
}
trap cleanup EXIT

OUTPUT=$(timeout 4s stdbuf -oL "$BINARY" \
    -l 0 \
    --no-huge \
    --no-pci \
    --vdev=net_null0 \
    --vdev=net_null1 \
    --file-prefix=alb_eal_init_test \
    --log-level=eal,info \
    -m 1024 \
    -- "$CONFIG_FILE" 5678 \
    2>&1) || true

# Port must come up (net_null gives a MAC)
if echo "$OUTPUT" | grep -q "Port 0 MAC:"; then
    echo "PASS: EAL init and port setup succeeded"
    exit 0
fi

echo "FAIL: Port 0 did not initialize"
echo "$OUTPUT"
exit 1
