#!/usr/bin/env bash
# End-to-end smoke of the generator CLI in stub mode: given a canned metrics
# snapshot, the generator must emit source, compile a .so, pass the in-proc
# smoke test, and install libstrategy.so under ./strategies/.

set -euo pipefail

workdir="$(mktemp -d)"
trap "rm -rf $workdir" EXIT

strategies_dir="$workdir/strategies"
mkdir -p "$strategies_dir"

include_dir="$(dirname "$(readlink -f "$STRATEGY_HDR")")"

cat >"$workdir/snap.json" <<'EOF'
{
  "timestamp": 100,
  "window_sec": 5.0,
  "backends": [
    {"idx":0,"ip":"192.168.1.1","packets_sent":500,"packets_missed":250,"active_connections":0,"capacity_hint":50},
    {"idx":1,"ip":"192.168.1.2","packets_sent":500,"packets_missed":0,"active_connections":0,"capacity_hint":100},
    {"idx":2,"ip":"192.168.1.3","packets_sent":500,"packets_missed":0,"active_connections":0,"capacity_hint":150}
  ]
}
EOF

"$GENERATOR" \
    --feed "$workdir/snap.json" \
    --strategies-dir "$strategies_dir" \
    --include-dir "$include_dir" \
    --smoke-bin "$(readlink -f "$SMOKE_BIN")" \
    --stub --once

test -f "$strategies_dir/libstrategy.so"
echo "stub generator produced: $(stat -c '%s bytes' "$strategies_dir/libstrategy.so")"

"$SMOKE_BIN" "$strategies_dir/libstrategy.so"
echo "installed .so passes independent smoke test"
