# ALB — Application Load Balancer

High-performance load balancer with hot-swappable strategies and DPDK packet processing.

## Quick Start

```bash
# Prerequisites (Ubuntu 22.04)
sudo apt-get install -y dpdk-dev libnuma-dev
sudo curl -fSL https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
  -o /usr/local/bin/bazel && sudo chmod +x /usr/local/bin/bazel

# Build & test
bazel build //...
bazel test //...
```

## Traffic Generator

```bash
bazel-bin/packages/traffic-generator/traffic-generator --vdev=net_null0 -l 0,1,2
```

Requires 3+ lcores: main (stats), workers (TX), last worker (RX drain).

## Tests

| Test | Description |
|------|-------------|
| `config_test` | Parses YAML configs, verifies IP/port/mac/weight parsing |
| `strategy_test` | Loads strategy via dlopen, verifies round-robin routing |
| `traffic-generator_build_test` | Verifies DPDK linkage |
| `eal_init_test` | DPDK EAL init with virtual device |
| `tx_test` | Verifies nonzero TX throughput |

DPDK tests use `--no-huge --no-pci --vdev=net_null0` — no real NICs or hugepages needed.

## Packages

| Package | Description |
|---------|-------------|
| [balancer-strategies](packages/balancer-strategies/) | Pluggable load-balancing strategies (C++) |
| [config](packages/config/) | YAML config parser for backends (C) |
| [traffic-generator](packages/traffic-generator/) | DPDK packet generator (C) |
| [version-table](packages/version-table/) | Lock-free hot-swap table (C++) |

## Development

```bash
pip install pre-commit && pre-commit install
```
