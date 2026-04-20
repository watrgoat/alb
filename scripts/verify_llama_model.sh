#!/usr/bin/env bash
set -euo pipefail

# Smoke-test the local GGUF with llama-cli (from install_llama_cpp.sh).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL="${ALB_GGUF_PATH:-$ROOT/models/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf}"

if ! test -f "$MODEL"; then
	echo "error: model file not found: $MODEL" >&2
	echo "Run: ./scripts/download_llama_model.sh" >&2
	exit 1
fi

if ! cmp -s <(head -c 4 "$MODEL") <(printf 'GGUF'); then
	echo "error: missing or invalid GGUF: $MODEL" >&2
	echo "Run: ./scripts/download_llama_model.sh" >&2
	exit 1
fi

LLAMA_CLI=""
for c in llama-cli llama-cli-linux; do
	if command -v "$c" >/dev/null 2>&1; then
		LLAMA_CLI="$c"
		break
	fi
done

if test -z "$LLAMA_CLI"; then
	echo "error: llama-cli not on PATH (install llama.cpp first: sudo ./third_party/install_llama_cpp.sh)" >&2
	exit 1
fi

set +e
out=$("$LLAMA_CLI" -m "$MODEL" -n 24 -p "Reply with exactly: OK" 2>&1)
rc=$?
set -e

if test "$rc" -ne 0; then
	echo "error: llama-cli failed (exit $rc)" >&2
	echo "$out" >&2
	exit 1
fi

echo "$out" | tail -n 20
echo "verify_llama_model: llama-cli completed successfully"
