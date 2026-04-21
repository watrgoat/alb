# ALB — Full Project Guide

A DPDK-based layer-4 UDP load balancer with hot-swappable, dlopen'd
routing strategies and an LLM-driven controller that writes new
strategies from live metrics.

This document is the deep-dive. For a quickstart, see
[README.md](README.md). For the LLM controller specifically, see
[packages/llm-strategy/FULL_README.md](packages/llm-strategy/FULL_README.md).

---

## Table of contents

1. [What ALB does](#1-what-alb-does)
2. [High-level architecture](#2-high-level-architecture)
3. [The packet path](#3-the-packet-path)
4. [Configuration](#4-configuration)
5. [The Strategy ABI](#5-the-strategy-abi)
6. [Hot-swap machinery](#6-hot-swap-machinery)
7. [Built-in strategies](#7-built-in-strategies)
8. [LLM-driven strategy generation](#8-llm-driven-strategy-generation)
9. [Metrics pipeline](#9-metrics-pipeline)
10. [Traffic generator](#10-traffic-generator)
11. [Build system](#11-build-system)
12. [Tests](#12-tests)
13. [Running ALB](#13-running-alb)
14. [Developer workflows](#14-developer-workflows)
15. [Repository layout](#15-repository-layout)
16. [Known limitations](#16-known-limitations)

---

## 1. What ALB does

ALB listens for UDP packets on a configured port, picks one of N
backend servers per packet according to a pluggable **routing
strategy**, rewrites the Ethernet destination MAC, the IPv4
destination address, and the UDP destination port to match the chosen
backend, and re-emits the packet on a second DPDK port.

The **whole routing decision** is a single virtual call —
`Strategy::select(const StrategyInput&) -> ServerState*`. The strategy
lives in a shared object that's `dlopen`'d at startup, and the running
process watches `./strategies/libstrategy.so` via inotify. Replacing
that file atomically (via `rename(2)`) causes the ALB to load the new
implementation into an inactive slot, flip a single atomic index, wait
for the old slot's workers to drain, then `dlclose` the previous
handle. No restart, no dropped connections.

On top of that hot-swap primitive, the `llm-strategy` package ships a
controller that observes live per-backend metrics, asks Claude to
write a new strategy source file, compiles it, smoke-tests it in a
subprocess, and drops it into the watched directory — closing the
loop from "observed miss rate" to "new routing algorithm in
production" in a few seconds.

---

## 2. High-level architecture

```
                            ┌──────────────────────────┐
                            │  config/config.yaml      │ backends:
                            │  (IP, port, MAC, weight) │  ip/port/mac/weight
                            └───────────┬──────────────┘
                                        │
                                  alb_config_load
                                        │
                                        ▼
┌────────────────────────────────────────────────────────────────────┐
│                            alb (main.cpp)                          │
│                                                                    │
│  ├─ rte_eal_init                                                   │
│  ├─ port_init(RX/TX rings, mempool, promiscuous)  × N ports        │
│  ├─ ServerState server_states[N]                                   │
│  ├─ load_into_slot(&table.slots[0], "./strategies/libstrategy.so") │
│  │     (or load_fallback_slot(...) — built-in round-robin)         │
│  └─ launch lcores:                                                 │
│        ┌───────────────────┐        ┌───────────────────┐          │
│        │  manager_main     │        │  worker_main × K  │          │
│        │  (inotify on      │        │  (RX → select →   │          │
│        │   ./strategies/)  │        │   rewrite → TX)   │          │
│        └────────┬──────────┘        └─────────┬─────────┘          │
│                 │                             │                    │
│                 ▼                             ▼                    │
│          HotSwapTable<StrategySlotData>  ◀── active_index          │
│            slots[0], slots[1]              (atomic, 2-slot table)  │
└───────────────────────────┬────────────────────────────────────────┘
                            │
                            │ .so dropped in by any of:
                            ▼
          ┌─────────────────────────────────────────┐
          │  ./strategies/libstrategy.so            │
          │  (libteststrategy.so = round-robin)     │
          │  (libweightedstrategy.so = weighted)    │
          │  (llm-generated via generator.py)       │
          └─────────────────────────────────────────┘
```

Everything outside the dashed ALB boundary is a feeder: config, the
strategies themselves, the traffic generator (for load), and the LLM
controller. The ALB exposes one interface to the outside world — the
`.so` contract at `./strategies/libstrategy.so`.

---

## 3. The packet path

[src/strategy_loader.cpp :: worker_main](src/strategy_loader.cpp#L99-L200)
is the entire fast path. Per worker lcore, in a tight loop:

### 3.1 Active-slot tracking

Each worker remembers `my_index` — the slot it's currently holding a
reference to. If `strategy_table.active_index` has moved since last
tick, the worker destroys its current `Strategy` (on the old slot),
`release()`s the old slot, `acquire()`s the new one, and creates a
fresh `Strategy` via the new slot's `create` pointer. This is how a
single cooperating reader adopts a hot-swapped strategy:

```cpp
size_t idx = strategy_table.active_index.load(std::memory_order_acquire);
if (idx != my_index) {
    if (strat && my_index != SIZE_MAX) {
        strategy_table.slots[my_index].data->destroy(strat);
        strategy_table.slots[my_index].release();   // drop refcount
    }
    strategy_table.slots[idx].acquire();            // bump refcount
    strat = strategy_table.slots[idx].data->create(
        server_states, num_servers);
    my_index = idx;
}
```

Every worker that still has the old slot contributes `1` to
`old_slot.in_flight`; the manager busy-waits on `old_slot.idle()`
before `dlclose`-ing, so the old `.so` stays mapped for as long as
anyone's inside it.

### 3.2 RX → filter → select → rewrite → TX

For each DPDK port in the system:

```cpp
struct rte_mbuf *bufs[BURST_SIZE];
const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
// ... for each rx'd packet:
//   - parse rte_ether_hdr; drop non-IPv4
//   - parse rte_ipv4_hdr;  drop non-UDP
//   - parse rte_udp_hdr;   drop if dst_port != listen_port
//   - input.packet_hash = ip_hdr->src_addr ^ ip_hdr->dst_addr
//   - ss = strat->select(input)
//   - memcpy(eth_hdr->dst_addr, &ss->mac, 6)
//   - ip_hdr->dst_addr = ss->address
//   - udp_hdr->dst_port = config.backends[bidx].port
//   - recompute IPv4 header checksum
//   - zero UDP checksum (assumed offloaded / optional for v4)
// accumulate kept mbufs in bufs[0..nb_to_tx-1]
const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0, bufs, nb_to_tx);
// free any mbufs that tx_burst didn't accept
```

Notable details:

- **`port ^ 1`** — each packet RX'd on port `p` is TX'd on port
  `p^1`. That pairing is why `main.cpp` requires `nb_ports` to be
  even. In production this is a two-port NIC; in testing we use
  two `--vdev=net_null` devices that satisfy the same shape.
- **`BURST_SIZE = 32`** — chosen to fit comfortably inside L1 and
  match DPDK's tuned burst loops. Smaller bursts waste polling
  cycles; larger ones blow cache.
- **Header rewriting happens in place** on the mbuf. The Ethernet
  source stays as-is (whatever the NIC put there on RX); destination
  goes to the backend's MAC. IPv4 destination is rewritten from the
  `ServerState`. The `hdr_checksum` is recomputed; UDP checksum is
  zeroed (IPv4 UDP allows this).
- **No connection tracking.** ALB is stateless per packet. If you
  want session affinity, implement it inside the Strategy by
  hashing on `packet_hash`, which is currently `src_ip ^ dst_ip` —
  stable per flow given no NAT upstream.

### 3.3 What the manager does

[manager_main](src/strategy_loader.cpp#L202-L250) runs on its own
lcore, with `inotify_init1(IN_NONBLOCK)` watching `./strategies/` for
`IN_CLOSE_WRITE | IN_MOVED_TO`. On each event:

1. Filter to entries named `libstrategy.so`.
2. `load_into_slot(&strategy_table.inactive(), "./strategies/libstrategy.so")` —
   `dlopen(RTLD_NOW)`, `dlsym("create_strategy")`, `dlsym("destroy_strategy")`,
   stash into the inactive slot's data pointer.
3. `strategy_table.swap()` — the single atomic `active_index` flip.
4. Busy-wait on `old_slot.idle()` (which is `in_flight.load() == 0`),
   yielding with `rte_pause()`.
5. `dlclose(old_slot.dl_handle)` and clear it.
6. Print `"reload complete"`.

A `dlopen` failure on the new `.so` leaves the inactive slot stale
but the active slot untouched — the ALB keeps routing with the old
strategy, and the next rename will re-trigger this loop. No torn
state, no crash.

---

## 4. Configuration

### 4.1 Format

YAML. Example
([config/config.yaml](config/config.yaml)):

```yaml
backends:
  - ip: "192.168.1.100"
    port: 8080
    mac: "aa:bb:cc:dd:ee:ff"
  - ip: "192.168.1.101"
    port: 8080
    mac: "aa:bb:cc:dd:ee:f1"
    weight: 3      # optional, default 1
```

### 4.2 Parser

[packages/config](packages/config/) — a small C module on top of
`libyaml`. Entry point is `alb_config_load(filename, &config)` which
populates a `struct alb_config` with up to `ALB_MAX_BACKENDS = 64`
backends. Weights default to 1 when omitted; MACs are parsed into
`struct rte_ether_addr` for direct use in DPDK header writes.

`alb_config_print` dumps the parsed config to stdout — ALB calls this
at boot for visual confirmation.

### 4.3 ALB command line

```
alb <EAL args> -- <config.yaml> <listen_port>
```

- EAL args come first (DPDK owns argv until `rte_eal_init` consumes
  them). Typical invocation includes `-l 0-N` for lcore list, `-m
  <MB>` for memory, and `--vdev=...` for virtual devices in test.
- Application args after `--` are the config path and the UDP
  port to listen on (as an integer; it's `htons`'d internally).

---

## 5. The Strategy ABI

[packages/balancer-strategies/include/strategy.hpp](packages/balancer-strategies/include/strategy.hpp)
is *the* contract. Every `.so` the loader consumes must export:

```cpp
extern "C" Strategy *create_strategy(ServerState *servers, int count);
extern "C" void      destroy_strategy(Strategy *s);

class Strategy {
public:
    virtual ServerState *select(const StrategyInput &s) = 0;
    virtual ~Strategy() = default;
};

struct StrategyInput {
    uint32_t packet_hash;
    uint32_t packet_index;
};

struct ServerState {
    uint32_t address;            // ipv4
    uint64_t mac;
    uint32_t active_connections;
    uint32_t weight;
};
```

Hard rules the ABI implies:

- **`select()` must return a pointer inside the `servers[]` array**
  passed to `create_strategy`. Returning `nullptr`, or a pointer into
  some other array, means the worker dereferences garbage. The ALB's
  smoke tester
  ([packages/llm-strategy/src/smoke_tester.cpp](packages/llm-strategy/src/smoke_tester.cpp))
  explicitly verifies this for 100 successive calls.
- **C linkage** on the two `create_*`/`destroy_*` functions so
  `dlsym` resolves by name. C++ mangling would break the loader.
- **No globals with non-trivial destructors** inside the `.so`. When
  the manager `dlclose`s the old handle, those destructors would
  run at an unpredictable moment. Stateful strategies must keep
  their state on the `Strategy` instance itself (e.g. the
  round-robin counter in
  [test-strategy-impl.cpp:5](packages/balancer-strategies/strategies/test-strategy-impl.cpp#L5)).
- **`select()` is hot-path code.** No syscalls, no allocations per
  call, no unbounded loops.

`packet_hash` is currently computed by `worker_main` as
`src_ip ^ dst_ip` — stable per flow under no-NAT conditions. A
Strategy that wants session affinity can hash-bucket on this directly.
`packet_index` is a monotonically increasing per-worker sequence
number — useful for strategies that want a round-robin or striping
behavior without storing state.

---

## 6. Hot-swap machinery

### 6.1 `version-table`

[packages/version-table/include/table.hpp](packages/version-table/include/table.hpp).

```cpp
template <typename T> struct Slot {
    T *data = nullptr;
    void *dl_handle = nullptr;
    std::atomic<int32_t> in_flight{0};
    void acquire();     // fetch_add(1)
    void release();     // fetch_sub(1)
    bool idle() const;  // load() == 0
};

template <typename T, size_t N = 2> struct HotSwapTable {
    Slot<T> slots[N];
    std::atomic<size_t> active_index{0};
    Slot<T> &active();
    Slot<T> &inactive();
    void swap();
};
```

Two slots are enough for a one-pending-swap-at-a-time protocol:
`active` is read by workers; `inactive` is written by the manager.
`swap()` is a single atomic store on `active_index` — readers see
either the old or new value in a single memory operation. There's no
window where a worker can see a partially initialized slot.

The `SharedVersionTable` struct at the bottom of the file is
shared-memory scaffolding for a future cross-process variant — not
wired up yet.

### 6.2 `StrategySlotData`

[src/strategy_loader.hpp](src/strategy_loader.hpp) specializes the
generic slot for strategy loading:

```cpp
struct StrategySlotData {
    Strategy *(*create)(ServerState *, int);
    void      (*destroy)(Strategy *);
};
using StrategySlot = Slot<StrategySlotData>;
extern HotSwapTable<StrategySlotData> strategy_table;
```

Each slot holds the two resolved function pointers plus the `dl_handle`
from `dlopen`. Workers call `slot.data->create(...)` to get their own
Strategy instance; one Strategy is allocated per worker, not one
shared globally — that way workers don't contend on any per-Strategy
mutable state.

### 6.3 Inotify semantics

`manager_main` watches with `IN_CLOSE_WRITE | IN_MOVED_TO`. Two
write paths fire this:

- **Atomic rename** (what the LLM generator uses):
  `rename(".libstrategy.so.tmp", "libstrategy.so")` → `IN_MOVED_TO`.
  The target name appears fully-written in a single filesystem op.
- **Copy + close** (what the manual test does):
  `cp new.so libstrategy.so` → `IN_CLOSE_WRITE` after the writer
  closes the fd.

Both land in the same filter in `manager_main` (`strcmp(ev->name,
"libstrategy.so") == 0`). The manager doesn't care which; both
paths are equivalent from its point of view.

**Avoid partial-write races.** Writing directly with `cp` is
technically racy — you can trigger `IN_MOVED_TO` while the file is
half written. For programmatic replacement, always write to a temp
file and `rename(2)` into place. The LLM generator does this.

---

## 7. Built-in strategies

[packages/balancer-strategies/strategies/](packages/balancer-strategies/strategies/).

### 7.1 Round-robin

[test-strategy-impl.cpp](packages/balancer-strategies/strategies/test-strategy-impl.cpp).
Single `int current` member, increments mod `count` per call. Not
thread-safe by design — each worker has its own Strategy instance, so
no sharing.

### 7.2 Weighted

[weighted-strategy-impl.cpp](packages/balancer-strategies/strategies/weighted-strategy-impl.cpp).
`target = packet_hash % total_weight`, walk cumulative weights until
the bucket containing `target` is found. Stateless across calls.

Both compile to `.so`s via `cc_binary(... linkshared = True)`:
`libteststrategy.so` and `libweightedstrategy.so` respectively. Either
can be dropped into `./strategies/libstrategy.so` and the loader
picks it up.

### 7.3 Built-in fallback

The ALB main binary also has a **built-in** round-robin strategy
inside `strategy_loader.cpp` (not a `.so`):

```cpp
class RoundRobinStrategy : public Strategy { ... };
static StrategySlotData fallback_data;
void load_fallback_slot(StrategySlot *slot) { ... }
```

If `./strategies/libstrategy.so` doesn't exist at boot,
`load_fallback_slot` wires this built-in into slot 0. The ALB still
boots and routes; you can drop in a `.so` later to swap.

---

## 8. LLM-driven strategy generation

See [packages/llm-strategy/FULL_README.md](packages/llm-strategy/FULL_README.md)
for the deep dive (algorithm, prompt structure, smoke-test sandbox,
convergence test, water-filling controller math).

Short version: `packages/llm-strategy/src/generator.py` reads a
metrics snapshot (JSON), optionally calls Claude Haiku to write a
C++ source file implementing the Strategy ABI, compiles it with
`g++ -fPIC -shared -O2 -std=c++17`, runs it through a dedicated
smoke-tester subprocess, and `rename(2)`s the verified `.so` into
`./strategies/libstrategy.so`. The ALB picks it up through its
existing inotify path.

Falls back to a deterministic water-filling stub (no network, no API
key) for CI and offline use.

---

## 9. Metrics pipeline

[packages/llm-strategy/include/metrics.hpp](packages/llm-strategy/include/metrics.hpp)
+ [metrics.cpp](packages/llm-strategy/src/metrics.cpp).

Per-backend atomic counters bumped by the TX hot path:

```cpp
class MetricsCollector {
    void record_sent(int bidx, uint64_t n);
    void record_missed(int bidx, uint64_t n);
    void set_ip(int bidx, uint32_t ip);
    void set_capacity_hint(int bidx, uint32_t pps);
    void set_active_connections(int bidx, uint32_t n);
    MetricsSnapshot snapshot(uint64_t now_sec, double window_sec);
};
```

`snapshot()` returns deltas, not cumulative totals, since the last
call — which is what the controller needs for rate math.
Serialization via `to_json()` (for the prompt) and `to_csv_rows()`
(for the convergence plot and schema compatibility with the
top-level `traffic-stats.csv`).

The counters use relaxed atomics; single writer per backend from a
TX worker, single reader from the manager lcore. The model is
**coarse aggregates**, not packet-by-packet tracing.

---

## 10. Traffic generator

[packages/traffic-generator/traffic-generator.c](packages/traffic-generator/traffic-generator.c).

A standalone DPDK binary that floods a port with pre-formed UDP
packets. Useful for:

- Stress-testing the ALB itself (point it at ALB's RX port).
- Sanity-checking DPDK + a given NIC/vdev setup.

Architecture:
- **One main lcore** for stats (prints pps once per second to stdout).
- **N-1 TX lcores**, one per additional worker slot. Each holds a
  burst of 32 pre-built mbufs, bumps their refcount before every
  `rte_eth_tx_burst`, and decrements on any that weren't sent.
- **One RX lcore** that drains `rx_burst` into `rte_pktmbuf_free` —
  prevents the device queue from filling up.

Requires `-l 0,1,...,N-1` with N ≥ 3. Minimum: main + one TX + RX
drain.

Packet shape is hardcoded at compile time: `192.168.1.2:1234 ->
192.168.1.1:5678` with a 32-byte payload. If you need configurable
flows, edit the `DST_ADDR` / `SRC_ADDR` macros at the top.

---

## 11. Build system

### 11.1 Bazel module

[MODULE.bazel](MODULE.bazel). Uses Bzlmod (Bazel 7+). Deps:

- `rules_cc` for `cc_library`, `cc_binary`, `cc_test`.
- `hedron_compile_commands` (dev dep) — generates
  `compile_commands.json` for clangd / IDE integration via
  `bazel run //:refresh_compile_commands`.

Native `py_binary` and `sh_binary` / `sh_test` rules are used
directly for Python and shell targets; rules_python is not wired up
so Python targets rely on system `python3` and its site-packages.

### 11.2 DPDK wiring

[third_party/dpdk.bzl](third_party/dpdk.bzl) is a repository rule
that calls `pkg-config --cflags libdpdk` and
`pkg-config --libs libdpdk` at Bazel-configuration time, then
materializes two files into a synthetic external repo:

- `cflags.bzl` exports `DPDK_COPTS = [...]` for `load()` in BUILD
  files.
- `BUILD.bazel` defines a `cc_library(name = "dpdk", linkopts =
  [...])` target consumers depend on as `@dpdk`.

Two subtleties worth knowing:

1. The repo rule rewrites system `-I/usr/include/...` to `-isystem
   /usr/include/...`. Bazel's include scanner rejects `-I` paths
   outside the execution root, so plain `-I` with system paths
   breaks the sandbox. `-isystem` doesn't get scanned.
2. It filters out `-I` / `-isystem` paths containing `dbus` or
   `libnl`. DPDK's `libdpdk.pc` pulls those in transitively for
   link-time but doesn't actually `#include` from them at compile
   time. Keeping them around triggered
   `/usr/lib/x86_64-linux-gnu/dbus-1.0/include` sandbox errors on
   Ubuntu 22.04; dropping them makes `bazel test //...` clean.

If DPDK isn't installed or `libdpdk.pc` isn't on `PKG_CONFIG_PATH`,
the repo rule fails early with a clear message pointing at
`apt-get install pkg-config dpdk-dev libnuma-dev`.

### 11.3 Platform constraints

Everything that touches DPDK is gated with
`target_compatible_with = ["@platforms//os:linux"]`. The
`cc_library` for `strategy.hpp` is Linux-only too, via the same
constraint — simpler than carving exceptions.

---

## 12. Tests

```
bazel test //...
```

Runs everything below. Current count: 11 tests, all passing.

| Target | Kind | What it verifies |
|--------|------|------------------|
| [`//packages/config:config_test`](packages/config/test/config_test.c) | cc_test | YAML → `alb_config`: IP, port, MAC, weight, defaults |
| [`//packages/balancer-strategies:strategy_test`](packages/balancer-strategies/test/main.cpp) | sh_test | Round-robin strategy `.so` loads and cycles through backends |
| [`//packages/balancer-strategies:swap_test`](packages/balancer-strategies/test/swap_test.cpp) | sh_test | Loads RR + weighted `.so`s in one process, verifies distributions |
| [`//packages/traffic-generator:traffic-generator_build_test`](packages/traffic-generator/test_build.sh) | sh_test | Traffic generator binary links against DPDK |
| [`//packages/traffic-generator:eal_init_test`](packages/traffic-generator/test_eal_init.sh) | sh_test | Full EAL init with `--vdev=net_null` in CI (no huge pages, no PCI) |
| [`//packages/traffic-generator:tx_test`](packages/traffic-generator/test_tx.sh) | sh_test | Generator actually TX's a nonzero pps via `net_null` |
| [`//src:alb_build_test`](src/test_build.sh) | sh_test | ALB binary links with DPDK + yaml + dl |
| [`//src:alb_eal_init_test`](src/test_eal_init.sh) | sh_test | ALB boots to EAL init with virtual ports |
| [`//src:alb_strategy_reload_test`](src/test_strategy_reload.sh) | sh_test | ALB running with RR strategy, `rename(2)` a weighted one in, observes `"new strategy detected"` and `"reload complete"` in logs |
| [`//packages/llm-strategy:llm_convergence_test`](packages/llm-strategy/test/convergence_test.cpp) | cc_test | 180-second simulated scenario with 4 capacity phases; asserts per-backend `sent/cap ∈ [0.9, 1.1]` 20 s after each shift, aggregate miss rate < 5%, and code-path latency budgets (`select` p99, `compute_weights` p99, `HotSwapTable::swap` p99) |
| [`//packages/llm-strategy:llm_generator_stub_test`](packages/llm-strategy/test/stub_generator_test.sh) | sh_test | Runs the generator CLI in stub mode end-to-end: emits source, compiles, smoke tests, atomic installs |

### 12.1 DPDK tests in sandbox

The DPDK-linked tests all run with `--no-huge --no-pci
--vdev=net_null0 --vdev=net_null1` so they don't need hugepages,
real NICs, or root. The test harness chooses `-m 1024` (1 GB
memory, from the pool rather than hugepages) and
`--file-prefix=...` to isolate from any host DPDK state.

The `alb_strategy_reload_test` launches `alb` in the background,
sleeps 2 seconds for the manager to arm its inotify watch, does
`cp foo.so strategies/libstrategy.so.tmp && mv ...`, sleeps 1
second, kills ALB, and greps the log for the expected lines.

### 12.2 Manual / sudo tests

[test/run_test.sh](test/run_test.sh) is a root-required end-to-end
test using DPDK TAP devices:

1. Starts ALB on port 5678 with a 3-backend config.
2. Uses [test/send_udp.py](test/send_udp.py) (raw sockets, needs
   CAP_NET_RAW) to send UDP packets to `dtap0` and observe on
   `dtap1`.
3. `send_udp.py --verify-round-robin --expected-backends ...` checks
   distribution matches expectations.

Not in `bazel test` because it needs privileges and real TAP
interfaces.

---

## 13. Running ALB

### 13.1 Prerequisites (Ubuntu 22.04)

```bash
sudo apt-get install -y pkg-config dpdk-dev libnuma-dev libyaml-dev zip

# bazel via bazelisk
sudo curl -fSL \
  https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
  -o /usr/local/bin/bazel
sudo chmod +x /usr/local/bin/bazel
```

`zip` is used by Bazel's test outputs archiver — tests don't require
it unless you want outputs captured. `libyaml` backs the config
parser. `pkg-config` + `dpdk-dev` expose the `libdpdk.pc` the
Bazel repo rule consumes.

### 13.2 Build + smoke test

```bash
bazel build //...
bazel test //...
```

### 13.3 Run against virtual devices (no NIC, no root)

```bash
bazel-bin/src/alb \
    -l 0-2 --no-huge --no-pci \
    --vdev=net_null0 --vdev=net_null1 \
    --file-prefix=alb_local \
    -m 1024 \
    -- config/config.yaml 5678
```

Three lcores: main lcore (which returns to `rte_eal_mp_wait_lcore`),
a manager lcore, and a worker lcore. Anything past `--` is ALB's
own args: config path and listen port.

### 13.4 Hot-swap a strategy while ALB is running

```bash
# In another terminal
mkdir -p strategies
cp bazel-bin/packages/balancer-strategies/libweightedstrategy.so \
   strategies/.libstrategy.so.tmp
mv strategies/.libstrategy.so.tmp strategies/libstrategy.so
```

Watch the ALB log — you should see:

```
new strategy detected, reloading...
reload complete
```

### 13.5 Run against real NICs

Same invocation, minus `--vdev=...` and `--no-pci`, plus the correct
`-l`, PCI addresses, and whatever hugepage setup your host needs.
Specifics depend on your hardware; see DPDK docs.

### 13.6 Real-hardware convergence test

```bash
sudo ./packages/llm-strategy/test/run_4port_convergence.sh [DURATION_SEC]
```

Runs the same 4-port pipeline as
[test/run_4port_test.sh](test/run_4port_test.sh) plus the LLM
controller loop. `metrics_adapter.py` converts the XDP collector's
real measurements into a `MetricsSnapshot` with a synthetic
per-backend capacity schedule, the generator consumes that snapshot,
rewrites `./strategies/libstrategy.so`, and ALB's inotify watcher
hot-swaps. Output: `convergence-real.png` in the results dir, showing
observed per-backend rate tracking the synthetic capacity steps. Set
`SCHEDULE=path/to/caps.json` to customize the capacity schedule; set
`ANTHROPIC_API_KEY` to use Claude instead of the stub controller. See
[packages/llm-strategy/FULL_README.md](packages/llm-strategy/FULL_README.md#95-real-hardware-convergence-test-4-port)
for the full pipeline diagram and env knobs.

### 13.7 Drive it with the LLM generator

```bash
bazel build //packages/llm-strategy:generator \
            //packages/llm-strategy:smoke_tester

ANTHROPIC_API_KEY=... \
bazel-bin/packages/llm-strategy/generator \
    --feed        /path/to/metrics.json \
    --strategies-dir ./strategies \
    --include-dir packages/balancer-strategies/include \
    --smoke-bin   bazel-bin/packages/llm-strategy/smoke_tester \
    --model       claude-haiku-4-5 \
    --interval    5
```

Metrics feed: any process that writes the JSON schema emitted by
`MetricsSnapshot::to_json()`. For production, wire the ALB's
`MetricsCollector::snapshot()` output through a file (or stdout
tailed into the generator's `--feed -` stdin).

### 13.8 Regenerate the simulator convergence plot

```bash
bash packages/llm-strategy/test/run_convergence_plot.sh
```

Writes [packages/llm-strategy/test/convergence.png](packages/llm-strategy/test/convergence.png)
(four stacked subplots, shared Y, miss-rate summary at the bottom).

---

## 14. Developer workflows

### 14.1 Writing a new strategy

1. Copy [weighted-strategy-impl.cpp](packages/balancer-strategies/strategies/weighted-strategy-impl.cpp)
   as a starting point.
2. Implement `select()`. Return a pointer inside `servers[]`.
3. Add a `cc_binary(name = "libmystrategy.so", linkshared = True,
   srcs = [...], deps = [":strategy"])` entry in
   [packages/balancer-strategies/BUILD.bazel](packages/balancer-strategies/BUILD.bazel).
4. `bazel build //packages/balancer-strategies:libmystrategy.so`.
5. `cp bazel-bin/.../libmystrategy.so strategies/libstrategy.so`
   (or `rename(2)` atomically).

### 14.2 Refreshing clangd compile commands

```bash
bazel run //:refresh_compile_commands
```

Regenerates `compile_commands.json` at repo root from the targets
listed in [BUILD.bazel](BUILD.bazel). Restart clangd / your IDE
after.

### 14.3 Pre-commit hooks

```bash
pip install pre-commit && pre-commit install
```

Repo-wide formatting and lint checks run on every commit.

### 14.4 Debugging a stuck reload

`manager_main` spins on `!old_slot.idle()` before `dlclose`. If a
worker lcore has crashed or is blocked, `in_flight` stays at 1 and
the manager hangs forever. Symptoms: `"new strategy detected"` logs
but never `"reload complete"`. Fix by investigating the worker,
not by papering over the hang.

---

## 15. Repository layout

```
alb/
├── BUILD.bazel                       # refresh_compile_commands
├── MODULE.bazel                      # bazel deps (rules_cc, hedron)
├── WORKSPACE.bazel                   # local DPDK via repository rule
├── README.md                         # quickstart
├── FULL_README.md                    # this file
│
├── src/                              # the alb binary
│   ├── main.cpp                      # EAL init, port setup, lcore dispatch
│   ├── strategy_loader.{hpp,cpp}     # worker_main + manager_main
│   ├── test_build.sh                 # sh_test: binary links
│   ├── test_eal_init.sh              # sh_test: EAL init with vdev
│   └── test_strategy_reload.sh       # sh_test: hot-swap .so end-to-end
│
├── packages/
│   ├── balancer-strategies/
│   │   ├── include/strategy.hpp      # THE ABI
│   │   ├── strategies/
│   │   │   ├── test-strategy-impl.cpp        # round-robin
│   │   │   └── weighted-strategy-impl.cpp    # weighted
│   │   └── test/
│   │       ├── main.cpp                      # strategy_test
│   │       └── swap_test.cpp                 # swap_test
│   │
│   ├── config/                        # YAML → alb_config
│   │   ├── include/config.h
│   │   ├── src/config.c
│   │   └── test/config_test.c
│   │
│   ├── llm-strategy/                  # LLM controller loop
│   │   ├── FULL_README.md             # deep dive on this package
│   │   ├── include/metrics.hpp
│   │   ├── src/
│   │   │   ├── metrics.cpp
│   │   │   ├── stub_generator.{hpp,cpp}       # water-filling controller
│   │   │   ├── smoke_tester.cpp               # subprocess sandbox
│   │   │   └── generator.py                   # Claude driver + stub fallback
│   │   └── test/
│   │       ├── convergence_test.cpp
│   │       ├── plot_convergence.py
│   │       ├── run_convergence_plot.sh
│   │       ├── stub_generator_test.sh
│   │       └── convergence.png
│   │
│   ├── traffic-generator/             # DPDK UDP flood generator
│   │   ├── traffic-generator.c
│   │   ├── test_build.sh
│   │   ├── test_eal_init.sh
│   │   └── test_tx.sh
│   │
│   └── version-table/                 # HotSwapTable<T>
│       └── include/table.hpp
│
├── third_party/
│   ├── BUILD.bazel
│   └── dpdk.bzl                       # pkg-config → cc_library @dpdk
│
├── config/
│   └── config.yaml                    # sample backend config
│
├── test/                              # manual / sudo-required tests
│   ├── run_test.sh                    # TAP-device end-to-end
│   └── send_udp.py                    # raw-socket helper
│
└── traffic-stats.csv                  # sample traffic pattern (used by PROMPT.md)
```

---

## 16. Known limitations

### 16.1 Functional gaps

- **Stateless per-packet routing only.** No connection tracking, no
  affinity, no health checks. A strategy can synthesize affinity
  via `packet_hash`, but the ALB itself has no notion of "session".
- **Single listen port.** `listen_port` is a single `uint16_t`; to
  route multiple UDP services, you need multiple ALB instances.
- **Two-port-per-pair model.** `port ^ 1` in `worker_main` hard-codes
  the "RX on port p, TX on port p^1" pairing. Works for the common
  2-port NIC case; for more flexible topologies, generalize.
- **Weights are static in the config.** Dynamic weight changes
  require swapping the strategy (which is what the LLM controller
  does) or an out-of-band mechanism.

### 16.2 Operational

- **DPDK prerequisites are real.** `dpdk-dev + libnuma-dev +
  pkg-config` minimum; hugepages + IOMMU + PCI for production.
- **No metrics export to anything.** `MetricsCollector::snapshot()`
  produces a JSON blob, but nothing wires it to Prometheus,
  StatsD, etc. The LLM controller consumes it directly via file
  or stdin. In production you'd want a proper exporter.
- **Manager busy-waits** on `old_slot.idle()`. Fine given the
  slot-drain window is milliseconds, but it spins on a single
  lcore. Not a thread; doesn't preempt workers; but consumes CPU.
- **LLM controller spends real tokens.** Cached prefixes help but
  output is always un-cached. Run in stub mode (`--stub`) for any
  extended testing.

### 16.3 Security

- **`./strategies/libstrategy.so` is arbitrary code.** Anyone who
  can write to that directory executes in the ALB's address space.
  Lock down filesystem permissions.
- **LLM-generated code is not sandboxed** beyond the 10-second
  subprocess smoke test. No seccomp, no namespaces, no resource
  limits. Fine for trusted operator use; do not expose the
  controller to untrusted prompt sources.

### 16.4 Not implemented / scaffolding

- **`SharedVersionTable`** in `version-table` is a struct layout
  for future cross-process hot-swap; no runtime uses it yet.
- **`Strategy::update()`** is commented out in `strategy.hpp` as a
  TODO for program-to-library update communication. The LLM loop
  sidesteps this by regenerating the whole strategy from scratch.
