#!/bin/bash
# Test that the traffic generator actually transmits packets.
# Uses net_null virtual device (accepts all TX, returns nothing on RX).
# Runs for a few seconds and checks that TX pps output appears.
set -e

OUTPUT=$(timeout 4s "$BINARY" \
    --vdev=net_null0 \
    --no-huge \
    -l 0,1,2 2>&1) || true

# Should see at least one TX stats line with nonzero pps
if ! echo "$OUTPUT" | grep -qE "TX: [1-9][0-9]* pps"; then
    echo "FAIL: No TX packets detected"
    echo "$OUTPUT"
    exit 1
fi

echo "PASS: Traffic generator is transmitting packets"
