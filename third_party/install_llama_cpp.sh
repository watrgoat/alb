#!/usr/bin/env bash
set -euo pipefail

# Build and install llama.cpp from source.
# Installs headers, libraries, and binaries to PREFIX (default /usr/local).
#
# Usage:
#   ./third_party/install_llama_cpp.sh              # install to /usr/local
#   PREFIX=/opt/llama ./third_party/install_llama_cpp.sh
#   LLAMA_CPP_TAG=b8748 ./third_party/install_llama_cpp.sh

PREFIX="${PREFIX:-/usr/local}"
LLAMA_CPP_TAG="${LLAMA_CPP_TAG:-b8748}"
LLAMA_CPP_REPO="https://github.com/ggml-org/llama.cpp.git"
BUILD_DIR="$(mktemp -d)"

if ! command -v cmake >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1 || ! command -v g++ >/dev/null 2>&1; then
	echo "error: need cmake, git, and g++ on PATH." >&2
	echo "On Ubuntu: sudo apt-get install -y cmake git build-essential" >&2
	exit 1
fi

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

echo "==> Cloning llama.cpp @ ${LLAMA_CPP_TAG}"
git clone --depth 1 --branch "$LLAMA_CPP_TAG" "$LLAMA_CPP_REPO" "$BUILD_DIR/llama.cpp"

echo "==> Building llama.cpp"
cmake -S "$BUILD_DIR/llama.cpp" -B "$BUILD_DIR/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DLLAMA_BUILD_TESTS=OFF \
    -DLLAMA_BUILD_EXAMPLES=ON \
    -DLLAMA_BUILD_SERVER=ON

cmake --build "$BUILD_DIR/build" -j "$(nproc)"

echo "==> Installing to ${PREFIX}"
cmake --install "$BUILD_DIR/build"

echo "==> Generating pkg-config file"
PC_DIR="${PREFIX}/lib/pkgconfig"
mkdir -p "$PC_DIR"
cat > "$PC_DIR/llama.pc" <<EOF
prefix=${PREFIX}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: llama
Description: LLM inference in C/C++ (llama.cpp)
Version: ${LLAMA_CPP_TAG}
Cflags: -I\${includedir}
Libs: -L\${libdir} -lllama -lggml -lggml-base -lm -lstdc++ -lpthread
EOF

echo "==> Done. Verify with: pkg-config --exists llama && echo ok"
echo ""
echo "Model: Llama 3.1 8B Instruct (GGUF, not in git): ./scripts/download_llama_model.sh"
echo "  https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct"
