# ALB — Application Load Balancer

A modular application load balancer with pluggable strategies and a DPDK-based traffic generator.

## Prerequisites

Linux host (Ubuntu 22.04 recommended):
Non-Linux platforms are unsupported.

```bash
# Install DPDK and build dependencies
sudo apt-get update
sudo apt-get install -y dpdk-dev libnuma-dev

# Install Bazelisk (provides the `bazel` command, auto-downloads the right Bazel version)
sudo curl -fSL https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
  -o /usr/local/bin/bazel && sudo chmod +x /usr/local/bin/bazel
```

## Build

```bash
bazel build //...
```

## Test

Test policy:

```bash
# Native Linux host — run all tests that matter
bazel test //...

# CI Linux — run CI suite
bazel test //... --test_tag_filters=ci
```

### Test inventory

| Test | Package | What it does | `ci` |
|------|---------|-------------|:---:|
| `strategy_test` | balancer-strategies | Loads `libteststrategy.so` via dlopen, creates 3 servers, sends 10 packets through round-robin, verifies correct routing | yes |
| `traffic-generator_build_test` | traffic-generator | Verifies the traffic-generator binary linked successfully against DPDK | yes |
| `eal_init_test` | traffic-generator | Starts the binary with a `net_null` virtual device, verifies DPDK EAL initializes and Port 0 comes up | yes |
| `tx_test` | traffic-generator | Same setup, runs for ~3s, verifies the stats thread reports nonzero TX packets per second | yes |

The DPDK runtime tests (`eal_init_test`, `tx_test`) use virtual devices so they don't need real NICs or hugepages: `--no-huge --no-pci --vdev=net_null0 -m 1024`. Each test uses a unique `--file-prefix` to avoid DPDK lock file collisions.

## Running the traffic generator

On a Linux machine with DPDK-capable NICs:

```bash
bazel-bin/packages/traffic-generator/traffic-generator --vdev=net_ring0 --vdev=net_ring0 -l 0,1,2
```

Requires at minimum 3 lcores: 1 for stats, 2..n-1 for TX, n for RX.

## Project structure

```
packages/
  balancer-strategies/   # Pluggable load-balancing strategy library (C++)
    include/strategy.h   #   Abstract Strategy base class
    strategies/          #   Strategy implementations (RoundRobinBasic)
    test/                #   dlopen-based test harness
  traffic-generator/     # DPDK packet generator for testing (C)
third_party/
  dpdk.bzl               # Bazel repository rule — wraps pkg-config for DPDK
.github/workflows/       # CI — builds and tests on every PR
```
