#!/bin/bash
# Verify the alb binary was linked successfully.
# We can't run it without DPDK runtime (hugepages, NICs).
set -e
test -x "$BINARY"
echo "alb binary linked OK"
