# ALB — Application Load Balancer

A modular application load balancer with pluggable strategies and a DPDK-based traffic generator.

## Prerequisites

DPDK is Linux-only. On macOS, use the devcontainer:

```bash
# VS Code
# Open the repo, then "Reopen in Container" from the command palette

# CLI (requires devcontainer CLI)
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

## Build

Inside the devcontainer (or any Linux environment with DPDK and Bazel installed):

```bash
# Build everything
bazel build //...

# Run all tests (CI / native Linux)
bazel test //...

# Run only tests that work locally in devcontainer (no DPDK runtime needed)
bazel test //... --test_tag_filters=local
```

## Running the traffic generator

```bash
bazel-bin/packages/traffic-generator/traffic-generator --vdev=net_ring0 --vdev=net_ring0 -l 0,1,2
```

Requires at minimum 3 lcores: 1 for stats, 2..n-1 for TX, n for RX.

## Project structure

```
packages/
  balancer-strategies/   # Pluggable load-balancing strategy library
  traffic-generator/     # DPDK packet generator for testing
third_party/
  dpdk.bzl               # Bazel repository rule (pkg-config wrapper)
.devcontainer/           # Docker dev environment with DPDK + Bazel
```
