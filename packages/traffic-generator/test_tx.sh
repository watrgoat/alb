#!/bin/bash
# Test that the traffic generator actually transmits packets.
set -e

OUTPUT=$(timeout 4s "$BINARY" \
    -l 0,1,2 \
    --no-huge \
    --no-pci \
    --vdev=net_null0 \
    --file-prefix=tx_test \
    -m 1024 \
    2>&1) || true

echo "--- RAW OUTPUT ---"
echo "$OUTPUT"
echo "--- END OUTPUT ---"

# Should see at least one TX stats line with nonzero pps
if echo "$OUTPUT" | grep -qE "TX: [1-9][0-9]* pps"; then
    echo "PASS: Traffic generator is transmitting packets"
    exit 0
fi

echo "FAIL: No TX packets detected"
exit 1
