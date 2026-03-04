#!/bin/bash
# Verify the traffic-generator binary was linked successfully.
# We can't run it without DPDK runtime (hugepages, NICs).
set -e
test -x "$BINARY"
echo "traffic-generator binary linked OK"
