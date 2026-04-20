#!/usr/bin/env bash
set -euo pipefail

# Download Llama 3.1 8B Instruct as GGUF into ./models/ (gitignored).
# Same base weights as https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct
# (GGUF quant from https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF).
# You must comply with Meta's Llama 3.1 license when using these weights.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODEL_DIR="${MODEL_DIR:-$ROOT/models}"
FILENAME="${MODEL_FILENAME:-Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf}"
OUT="${MODEL_DIR}/${FILENAME}"
URL="https://huggingface.co/bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/${FILENAME}"

is_gguf() {
	local f="$1"
	test -f "$f" || return 1
	test "$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null)" -ge 8 || return 1
	cmp -s <(head -c 4 "$f") <(printf 'GGUF')
}

mkdir -p "$MODEL_DIR"

if is_gguf "$OUT"; then
	echo "Model already present and valid GGUF: $OUT"
	exit 0
fi

if test -f "$OUT"; then
	echo "Removing invalid or partial file: $OUT"
	rm -f "$OUT"
fi

echo "Downloading to $OUT (resume supported with curl -C -) ..."
curl -fL --retry 5 --retry-delay 2 -C - -o "$OUT" "$URL"

if ! is_gguf "$OUT"; then
	echo "error: downloaded file is not a valid GGUF: $OUT" >&2
	exit 1
fi

echo "OK: $OUT"
