#!/usr/bin/env bash
# Regenerate packages/llm-strategy/test/convergence.png from a fresh
# simulation run. Safe to re-run; overwrites the CSVs and PNG.
#
# Usage:  packages/llm-strategy/test/run_convergence_plot.sh
#         (from repo root, or wherever — resolves paths itself)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../../.." && pwd)"
cd "$repo_root"

out_dir="$here"
csv="$out_dir/convergence.csv"
markers="$out_dir/markers.csv"
png="$out_dir/convergence.png"

bazel build //packages/llm-strategy:convergence_runner \
            //packages/llm-strategy:plot_convergence

bazel-bin/packages/llm-strategy/convergence_runner \
    --csv "$csv" --markers "$markers"

# The py_binary launcher script handles PYTHONPATH for its deps.
bazel-bin/packages/llm-strategy/plot_convergence \
    --csv "$csv" --markers "$markers" --out "$png"

echo "wrote $png"
