# llm-strategy — In-Depth Guide

This package drives the ALB's hot-swap-able strategy socket with a
controller that reads live backend metrics, chooses new routing weights
(or has an LLM write a whole new strategy source file), compiles the
result to a shared object, smoke-tests it in a subprocess, and installs
it atomically into `./strategies/libstrategy.so`. The running `alb`
binary's `manager_main` picks it up via inotify and swaps slots.

The package also ships an in-process convergence harness and a plotting
driver so you can watch that loop converge under a simulated shifting
backend capacity schedule.

This document explains every moving piece — the ABI it plugs into, the
metrics data path, the generator loop, the water-filling controller,
the convergence test methodology, the plot, and how to operate it live
against a running ALB.

---

## 1. Where this sits in the larger system

The ALB's hot-swap machinery exists independently of this package and
was already in place before llm-strategy was added:

```
                      metrics snapshot (JSON)
                              │
                              ▼
┌──────────────────────────────────────────────────┐
│ llm-strategy/generator.py                        │
│   - reads snapshot                               │
│   - builds prompt (ABI + history + snapshot)     │
│   - calls Claude, or falls back to stub          │
│   - compiles to .so                              │
│   - smoke-tests in subprocess                    │
│   - atomic rename into strategies/               │
└─────────────────┬────────────────────────────────┘
                  │ libstrategy.so (IN_MOVED_TO)
                  ▼
┌──────────────────────────────────────────────────┐
│ src/strategy_loader.cpp :: manager_main          │
│   - inotify watches ./strategies/                │
│   - dlopen new .so into the inactive Slot        │
│   - HotSwapTable::swap() — active_index flips    │
│   - wait for old slot to drain (in_flight == 0)  │
│   - dlclose the old handle                       │
└─────────────────┬────────────────────────────────┘
                  │ new Strategy is live
                  ▼
┌──────────────────────────────────────────────────┐
│ src/strategy_loader.cpp :: worker_main           │
│   - per-lcore RX/TX loop (DPDK)                  │
│   - acquire()/release() around active slot       │
│   - strat->select(input) picks backend per packet│
│   - MetricsCollector increments on TX success    │
└──────────────────────────────────────────────────┘
```

The contract between generator and ALB is **only** the `.so` file and
the `Strategy` ABI inside it. No shared memory, no RPC, no extra
protocol. Everything else you see in this package is plumbing around
that single interface.

---

## 2. The Strategy ABI (non-negotiable)

Defined in
[packages/balancer-strategies/include/strategy.hpp](../balancer-strategies/include/strategy.hpp).
Any `.so` installed into `./strategies/libstrategy.so` must conform.

```cpp
struct StrategyInput {
    uint32_t packet_hash;
    uint32_t packet_index;
};

struct ServerState {
    uint32_t address;          // ipv4
    uint64_t mac;              // mac
    uint32_t active_connections;
    uint32_t weight;
};

class Strategy {
public:
    virtual ServerState *select(const StrategyInput &s) = 0;
    virtual ~Strategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count);
extern "C" void      destroy_strategy(Strategy *s);
```

Key invariants the loader and the generator both rely on:

- `select()` must return a pointer that lives in the `servers` array
  passed to `create_strategy`. Anything else and the ALB will deref
  garbage. The smoke tester explicitly checks this.
- `create_strategy` / `destroy_strategy` must have C linkage so
  `dlsym` can find them by name.
- The `Strategy` instance must own no state that outlives the slot.
  When a new strategy is swapped in, the old `Strategy*` is destroyed
  and the old `.so` is `dlclose`'d — any globals with non-trivial
  destructors living inside that `.so` would run at the wrong time.
- `select()` runs on the hot path under `slot.acquire()` —
  no syscalls, no blocking, no unbounded loops.

The generator's system prompt ([generator.py:SYSTEM_PROMPT](src/generator.py#L26-L46))
spells these constraints out to Claude verbatim.

---

## 3. Hot-swap table — the thing strategies plug into

[packages/version-table/include/table.hpp](../version-table/include/table.hpp)
defines `HotSwapTable<T, N=2>`: N slots, one active index, each slot
has its own `in_flight` refcount. `manager_main` loads a new strategy
into the inactive slot, flips `active_index`, then spins on
`old_slot.idle()` (in_flight == 0) before `dlclose`'ing. Workers use
`acquire()`/`release()` around their use of the active slot's data.

The generator never touches this table directly. It just writes a file
into `./strategies/` and the loader does the rest.

The convergence test does touch it directly (lines
[103-108](test/convergence_test.cpp#L103-L108) and
[180-187](test/convergence_test.cpp#L180-L187)) to prove that the
direct `HotSwapTable::swap()` path works too — both paths are supported
by the design, and we exercise both.

---

## 4. Metrics collector

[include/metrics.hpp](include/metrics.hpp),
[src/metrics.cpp](src/metrics.cpp).

The collector is per-backend, with atomic counters that workers can
bump on the TX hot path without locks:

```cpp
class MetricsCollector {
    std::vector<BackendCounters> counters_;   // monotonic totals
    std::vector<uint64_t>        last_sent_;  // for delta computation
    std::vector<uint64_t>        last_missed_;
public:
    void record_sent(int bidx, uint64_t n = 1);
    void record_missed(int bidx, uint64_t n);
    MetricsSnapshot snapshot(uint64_t now_sec, double window_sec);
};
```

### What's recorded

- `packets_sent` — bump after a successful `rte_eth_tx_burst`,
  bucketed by `bidx` (the index the Strategy returned). In production
  this hooks into
  [src/strategy_loader.cpp :: worker_main](../../src/strategy_loader.cpp)
  right after the TX burst succeeds. In the simulator it's per-packet.
- `packets_missed` — caller-reported drops. In production this would
  come from backend-reported drop counters. In the test, the simulated
  backend computes `miss = max(0, sent - capacity)` per window.
- `active_connections` — copied from `ServerState` at snapshot time.
- `capacity_hint` — externally set; in the test, the scenario updates
  it whenever the capacity schedule changes.

### How the snapshot works

`snapshot(now, window_sec)` returns `MetricsSnapshot`:

- `timestamp_sec`, `window_sec`
- `backends[i]`: `{ backend_idx, ip, packets_sent, packets_missed,
  active_connections, capacity_hint }`

where `packets_sent` and `packets_missed` are **deltas since the last
call**, not totals. That makes the per-window math the generator wants
trivial: `miss_rate[i] = packets_missed[i] / packets_sent[i]`.

`to_json()` serializes the snapshot for the LLM prompt.
`to_csv_rows()` serializes for the convergence plot.
Schema matches `traffic-stats.csv`'s
`timestamp,ip,packets_delta` plus `missed` and `capacity_hint`
columns, per the PROMPT.md spec.

### Thread-safety model

One writer per backend on the TX worker, one reader on the manager.
`std::atomic<uint64_t>` with relaxed ordering is sufficient — we
don't care about cross-backend ordering of increments, only that
individual counter reads are torn-free. `set_capacity_hint` /
`set_active_connections` are plain uint32s; only written from the
manager, only read during snapshot, so no atomics needed.

---

## 5. Generator loop — end to end

[src/generator.py](src/generator.py) is the driver. High-level flow
per cycle:

```
snapshot ─▶ build prompt ─▶ Claude ─▶ C++ source ─▶ g++ -shared ─▶ smoke ─▶ rename
                              │
                              │ (compile or smoke failure)
                              ▼
                         feed diagnostic back
                         → regenerate (up to 3 attempts)
```

### 5.1 Prompt construction

The prompt has four parts, in order, and the first two are cached on
the Anthropic side via `cache_control: ephemeral` so the unchanging
prefix doesn't re-tokenize every cycle
([generator.py:call_claude](src/generator.py#L71-L86)):

1. **System prompt** (cached) — constraints: include only `<cstdint>`,
   no threads/I/O/globals with non-trivial dtors, must implement the
   ABI verbatim, must return a pointer inside `servers[]`, objective
   is `minimize sum(packets_missed) s.t. throughput within 5% of
   current`.
2. **ABI** (cached) — the verbatim contents of `strategy.hpp`, under a
   banner comment.
3. **Current snapshot** (volatile) — the JSON snapshot.
4. **History buffer** (volatile, capped at last 3 attempts) — each
   entry is `(attempt_id, miss_rate_when_generated, source[:600])`.
   Older attempts are dropped rather than summarized, keeping token
   budget under ~8k per the spec.

### 5.2 Compile

`g++ -fPIC -shared -O2 -std=c++17 -I<strategy.hpp dir>
source.cpp -o candidate.so`.

The include dir is passed via `--include-dir`; in the Bazel setup
that's `packages/balancer-strategies/include` (a filegroup was added
to `balancer-strategies/BUILD.bazel` so it's reachable as runfiles
data from the `py_binary`).

On compile failure, the first ~2000 chars of `stderr` are captured
and prepended to the system prompt for the next attempt as
`"Previous attempt failed to compile: <err> Fix it."`. This is what
lets Claude recover from e.g. wrong `select()` signatures — we saw
this happen in practice on first real invocation.

### 5.3 Smoke test (subprocess isolation)

Generated code is untrusted. We never `dlopen` a candidate `.so`
into the generator's own address space. Instead we fork a separate
process — the dedicated `smoke_tester` binary
([src/smoke_tester.cpp](src/smoke_tester.cpp)) — which:

1. `dlopen(RTLD_NOW)` the candidate.
2. Resolves `create_strategy` / `destroy_strategy` via `dlsym`.
3. Calls `create_strategy(servers, 3)` and checks non-null.
4. Runs 100 `select()` calls with varying hashes and **checks every
   returned pointer is inside the `servers` array** — this catches
   classic bugs where a buggy strategy returns `nullptr` or a
   computed pointer.
5. `destroy_strategy`, `dlclose`, exit 0.

Any crash (SEGV, abort) stays contained in the child. Exit nonzero →
diagnostic fed back into the next prompt, same as a compile error.

### 5.4 Atomic install

Once a candidate passes smoke, it's installed like this:

```python
shutil.copy2(so_path, strategies_dir / ".libstrategy.so.tmp")
os.rename(strategies_dir / ".libstrategy.so.tmp",
          strategies_dir / "libstrategy.so")
```

The loader's inotify watch is on `IN_CLOSE_WRITE | IN_MOVED_TO`.
`rename(2)` is atomic on a single filesystem and fires `IN_MOVED_TO`,
which is exactly what `manager_main` handles. No partial-write race
where the loader could see a half-written `.so`.

### 5.5 Falling back to the stub

If `ANTHROPIC_API_KEY` is unset, or if `--stub` is passed, the
generator skips the Claude call entirely and uses a deterministic
Python stub that emits a weighted strategy with weights computed
from the current snapshot
([generator.py:stub_weights](src/generator.py#L99-L114) and
[emit_stub_source](src/generator.py#L117-L148)). The stub algorithm
is simpler than the C++ water-filling controller — it does
observed-effective + 1.2x probe. It exists so:

- The Bazel `llm_generator_stub_test` sh_test can run end-to-end in
  CI with no network access.
- The generator is still useful if someone wants a deterministic
  controller loop without paying for API calls.

### 5.6 Signal handling and loop lifetime

Python `SIGINT` / `SIGTERM` flip a flag; the loop exits cleanly
after the current cycle, `shutil.rmtree` on the temp workdir.
`--once` causes a single cycle then exit. `--interval N` (default 5
seconds) polls the feed file in a loop when `--feed` points at a
file rather than `-` (stdin).

---

## 6. The water-filling controller (stub, in-process version)

The convergence test and unit test use a pure-C++ controller in
[src/stub_generator.cpp](src/stub_generator.cpp). Same conceptual
algorithm as `generator.py`'s stub, but more robust (symmetric
convergence).

### 6.1 Why not a simpler algorithm?

The obvious approach is **per-backend local estimation**:

```
if missed[i] > 0: cap_est[i] = sent[i] - missed[i]
else:             cap_est[i] = sent[i] * k   # probe factor
```

This is what I started with. The failure mode: after a capacity
change, backends whose allocated weight is *too high* snap down
instantly (one cycle). Backends whose allocated weight is *too low*
grow only by `k` per cycle. That asymmetry means convergence back to
a balanced state takes many cycles, during which the system is
dropping packets.

Concretely: in the phase 3 → phase 4 transition
(`[1500, 500, 1000]` → `[1000, 1000, 1000]`), backend 0's weight is
stuck high (from phase 3, when it had cap 1500). It drops packets
immediately. But backend 1's weight is stuck low (phase 3 cap was
500), so it receives too few packets. A pure per-backend rule grows
backend 1 only k× per cycle — say 5% at a time — and meanwhile
backend 0 keeps dropping until it reaches the new ceiling.

### 6.2 Water-filling

Instead, we redistribute *within* each cycle, preserving total
weight:

```
total_miss      = sum(missed)
total_good_cap  = sum(cap_est[i]   where missed[i] == 0)

for each backend i:
    if missed[i] > 0:
        cap_est[i] -= missed[i]              # snap to observed ceiling
    else:
        cap_est[i] += total_miss *
                      (cap_est[i] / total_good_cap)   # absorb proportionally

# edge cases:
# - total_miss == 0: probe all weights up 5%; snap any underutilized
#   estimate down to observed so future probes don't overshoot
# - all backends dropping: snap each to its own observed ceiling
```

The key property: **sum of `cap_est` is invariant across a cycle when
there's any non-dropping backend**. Weight that disappears from
droppers reappears on non-droppers proportional to their current
capacity share. Both directions move together.

### 6.3 Worked trace — phase 3 → phase 4

(`[1500, 500, 1000]` → `[1000, 1000, 1000]`, rate = 3000 pps, cycle
= 5 seconds.)

Starting weights just before t=150, steady from phase 3: roughly
`[8250, 2750, 5500]` (scaled by phase-1 probe inflation; ratios are
`3:1:2`). Total = 16500.

```
t=150–154  (caps = [1000, 1000, 1000])
  routing:  300 pps × w/W per backend per second
  sent     = [1500, 500, 1000] × 5s = [7500, 2500, 5000]
  missed   = [2500, 0, 0]         total_miss = 2500
  total_good_cap = 2750 + 5500 = 8250
  cap_est[0] = 8250 - 2500 = 5750
  cap_est[1] = 2750 + 2500 × 2750/8250 = 2750 + 833  = 3583
  cap_est[2] = 5500 + 2500 × 5500/8250 = 5500 + 1667 = 7167
  → w = [5750, 3583, 7167]

t=155–159
  sent/sec ≈ 300 × w/W = [1045, 652, 1303]
  missed   = [45, 0, 303] per sec × 5 = [227, 0, 1515]
  total_miss = 1742, total_good_cap = cap_est[1] only = 3583
  cap_est[0] = 5750 - 227 = 5523
  cap_est[1] = 3583 + 1742 × 1 = 5325    (it's the only good one)
  cap_est[2] = 7167 - 1515 = 5652
  → w = [5523, 5325, 5652]

t=160–164
  sent/sec ≈ [1004, 968, 1028]
  missed   ≈ [4, 0, 28] × 5 = [20, 0, 140]
  cap_est[0] = 5523 - 20  = 5503
  cap_est[1] = 5325 + 160 = 5485
  cap_est[2] = 5652 - 140 = 5512
  → w = [5503, 5485, 5512]   — balanced within 0.5%

t=165–169
  sent/sec ≈ [1000, 997, 1002]   — within [0.9, 1.1] ✓
```

Total miss over the 20-second window: ≈ 4000, about 1.3% of the
6000 packets routed in those 20 s. Assertion passes.

### 6.4 Why the "probe up 5%" branch exists

Without the `total_miss == 0` branch, a steady-state system never
reveals when backends gain headroom. Suppose all three backends have
cap 1000 but `cap_est` is stuck at `[500, 500, 500]`. Total weight =
1500 < rate = 3000 → each backend sees sent = 1000 per second →
caps are hit exactly, no miss. The controller has no signal.

By probing up 5% per no-miss cycle, the controller grows weights
until somebody starts dropping (revealing a ceiling) or a phase
change forces a snap-down. The bottom subplot of the convergence
plot shows this as a gentle upward drift during steady periods.

### 6.5 Initialization

`cap_est_.assign(n, 100.0)` on first call. After the first cycle,
each backend's estimate is either set from observed sent (probe-up
snapped to `max(cap_est × 1.05, sent)`) or from observed effective
throughput — either way, the initial 100 is overwritten within one
cycle.

---

## 7. Convergence test — methodology

[test/convergence_test.cpp](test/convergence_test.cpp). Built as both
a `cc_test` (asserts, no outputs) and a `cc_binary`
(`convergence_runner`, writes CSVs).

### 7.1 Scenario

- 3 simulated backends.
- Aggregate traffic rate: **3000 pps** (the PROMPT.md example was
  300 pps; bumped 10× to reduce hash-distribution variance — see
  §7.3).
- Capacity schedule (also scaled 10×, ratios preserved from spec):

  | t (s) | cap₀ | cap₁ | cap₂ |
  |-------|------|------|------|
  |   0   | 1000 | 1000 | 1000 |
  |  30   |  500 | 1000 | 1500 |
  |  90   | 1500 |  500 | 1000 |
  | 150   | 1000 | 1000 | 1000 |

- Simulated duration: 180 s.
- Generator cycle: every 5 s.
- Per-packet: distribute through the active `Strategy` (plain
  `WeightedStrategy` — same algorithm as
  [weighted-strategy-impl.cpp](../balancer-strategies/strategies/weighted-strategy-impl.cpp)).

### 7.2 Hot-swap path exercised

Every cycle:
1. `metrics.snapshot(t, 5.0)` — delta counters from this window.
2. `StubGenerator::compute_weights(snap)` — water-filling.
3. Write new weights into `server_states[].weight`.
4. `HotSwapTable::swap()` — toggles the active index.

This is the "direct" swap path — no compile, no dlopen, no file
writes. The compile + inotify + dlopen path is covered by
`llm_generator_stub_test` separately.

### 7.3 Why 3000 pps (not 300)

The WeightedStrategy does `target = packet_hash % total_weight`.
With 300 packets per second and weights summing to some W, the 300
samples form a rank-1 lattice on `[0, W)` — the distribution isn't
exactly uniform, it's only approximately so. Backend-allocation
noise at 300 packets/sec was frequently 10–15% deviation from the
expected ratio, which pushed the `[0.9, 1.1]` assertion right to
the edge.

At 3000 packets/sec, the same relative-variance argument gives
~4% deviation — safely inside the band. Ratios in the scenario
(1:1:1 → 1:2:3 → 3:1:2 → 1:1:1) are preserved by scaling caps
10× to match.

Additionally, `StrategyInput.packet_hash` in the simulator is fed
through a splitmix32 finalizer
([convergence_test.cpp:mix_hash](test/convergence_test.cpp#L36-L41))
rather than a raw `p * K` — the raw sequence has rank-1 bias bad
enough that even 3000 samples showed measurable skew for specific
(hash, W) combinations.

### 7.4 Assertions

Three checks, all must pass:

1. **Per-backend ratio after each transition.** For each entry in
   the capacity schedule (t = 0, 30, 90, 150), at t + 20 seconds,
   `sent[i] / capacity[i]` must be in `[0.9, 1.1]` for every
   backend. 20 s = 4 controller cycles — the water-filling algorithm
   typically converges in 2–3 cycles, so this has margin.
2. **Total miss rate over the full run.** `sum(missed) / sum(sent)`
   across all 180 seconds must be under **5%**. With 4 transitions
   × ~2000 dropped packets during each transient, plus ~0 miss
   during steady periods, we land around 2–3%.
3. **Code-path latency budgets.** Timestamps taken with
   `std::chrono::steady_clock` around each hot call:
   - `Strategy::select()` p99 < 5000 ns per packet
   - `StubGenerator::compute_weights()` p99 < 1 ms per cycle
   - `HotSwapTable::swap()` p99 < 500 µs per cycle

   These are intentionally loose — the point is to catch accidental
   regressions (alloc in hot path, O(n²) over backends, unexpected
   syscalls) rather than to assert absolute performance. `steady_clock`
   itself costs ~20–30 ns on x86, which sets the floor for the
   per-packet number.

The first check verifies each backend individually reaches its
target. The second verifies aggregate system behavior (not just
"one backend is happy while another suffers"). The third guards
against algorithmic complexity regressions in the hot paths.

### 7.5 CSV output

`convergence_runner --csv path --markers path` writes two files:

- `convergence.csv` — `timestamp,backend_idx,ip,packets_sent,
  packets_missed,capacity` per second per backend. 540 rows for a
  180 s × 3 backend run. Schema matches the production
  `traffic-stats.csv` schema plus the extra columns the spec
  called for.
- `markers.csv` — the capacity schedule, used by the plot driver
  to draw vertical markers.

The cc_test version never writes these, so Bazel's `outputs.zip`
archiving step doesn't try to zip anything. (Avoids a `zip`
command dependency in the test harness.)

---

## 8. The plot

[test/plot_convergence.py](test/plot_convergence.py). Four stacked
subplots with a shared X axis and shared Y limits across the three
backend subplots:

- **Top three**: one per backend.
  - Solid colored line: `packets_sent` (what the LB actually routed
    there).
  - Dashed black step line: `capacity` — the target the sent line
    should track.
  - Red-shaded region where `sent > capacity` — drops happening.
  - Thin red dashed line: `packets_missed`.
- **Bottom**: aggregate miss rate (5-second rolling mean), with a
  dotted horizontal reference at the 5% budget.
- **Vertical dotted grey lines**: capacity change events, annotated
  at the top with the new caps tuple.

Shared Y across the three backend subplots is deliberate: it makes
it visually obvious that backend 2 goes up to 1500 while backend 0
goes down to 500 in phase 2 (and vice-versa in phase 3) — same
ruler, direct comparison.

---

## 9. Running it

### 9.1 Just run the tests

```bash
bazel test //packages/llm-strategy/...
```

Runs `llm_convergence_test` (the cc_test with assertions) and
`llm_generator_stub_test` (end-to-end stub generator through compile
+ smoke + install). Offline, no network needed.

### 9.2 Regenerate the plot

```bash
bash packages/llm-strategy/test/run_convergence_plot.sh
```

Builds `convergence_runner` and `plot_convergence`, runs the
simulation, writes the CSVs and the PNG to
`packages/llm-strategy/test/`. Safe to re-run.

The script's steps unrolled:

```bash
bazel build //packages/llm-strategy:convergence_runner \
            //packages/llm-strategy:plot_convergence

bazel-bin/packages/llm-strategy/convergence_runner \
    --csv     packages/llm-strategy/test/convergence.csv \
    --markers packages/llm-strategy/test/markers.csv

bazel-bin/packages/llm-strategy/plot_convergence \
    --csv     packages/llm-strategy/test/convergence.csv \
    --markers packages/llm-strategy/test/markers.csv \
    --out     packages/llm-strategy/test/convergence.png
```

### 9.3 Live against a running ALB

With a real `alb` binary running, point the generator at the running
strategies dir and a source of metrics snapshots:

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

Each successful cycle will log `[cycle N] installed via attempt M
(mode=llm)` to stdout, and — over in the ALB process — the loader
will print its existing `new strategy detected, reloading...` and
`reload complete` messages from `manager_main`.

To force the offline stub path (no API key needed, no network):

```bash
bazel-bin/packages/llm-strategy/generator ... --stub
```

For a single cycle (testing):

```bash
bazel-bin/packages/llm-strategy/generator ... --once
```

### 9.4 Signals

`SIGINT` / `SIGTERM` → exit after current cycle, clean up temp dir.

### 9.5 Real-hardware convergence test (4-port)

The simulator in §7 is offline. To exercise the same controller loop
against a **live ALB** with real NIC traffic:

```bash
sudo ./packages/llm-strategy/test/run_4port_convergence.sh [DURATION]
```

Pipeline:

```
traffic-generator  P1 --cable--> P2  ALB  P3 --cable--> P4  XDP-collector
                                    │                         │
                                    ▼                         │
                          inotify(./strategies/)               │
                                    ▲                         │
                                    │                         ▼
                          libstrategy.so             traffic-stats.csv
                                    ▲                         │
             +----------------------+                         │
             │                                                │
        llm-generator ◀── snapshot.json ◀── metrics_adapter ◀-+
                                             (synthesizes caps)
```

Three new components on top of [test/run_4port_test.sh](../../test/run_4port_test.sh):

1. **[metrics_adapter.py](test/metrics_adapter.py)** — tails the XDP
   collector's `traffic-stats.csv`, applies a per-backend capacity
   schedule ([caps_schedule_default.json](test/caps_schedule_default.json)
   or your own via `SCHEDULE=...`), and writes a snapshot in the
   `MetricsSnapshot` schema the generator expects. Real backends
   don't actually drop, so `packets_missed` is synthesized as
   `max(0, observed_pps − cap_pps) × window_sec`. This converts the
   uncapped NIC loopback into a capacitated system for the controller.
2. **[generator.py](src/generator.py)** (reused) — runs with
   `--feed snapshot.json`, either `--stub` or with `ANTHROPIC_API_KEY`,
   rewrites `./strategies/libstrategy.so`. ALB's `manager_main` picks
   it up via its existing inotify path.
3. **[plot_4port_convergence.py](test/plot_4port_convergence.py)** —
   reads the collector CSV + capacity schedule + `start_time.txt`,
   plots one subplot per backend with synthetic-cap overlay, red
   shading where observed exceeded cap, vertical markers at schedule
   changes, and an aggregate subplot at the bottom.

Environment knobs:

| Var | Default | Meaning |
|-----|---------|---------|
| `P1..P4` | `enp4s0f{0..3}np{0..3}` | port names (match `run_4port_test.sh`) |
| `OUTDIR` | `test/results/<ts>-conv` | results dir |
| `SCHEDULE` | `caps_schedule_default.json` | capacity schedule |
| `ANTHROPIC_API_KEY` | unset → stub mode | if set, LLM path is used |
| `MODEL` | `claude-haiku-4-5` | LLM model id |
| `GEN_INTERVAL` | 5 s | generator poll / adapter emit interval |
| `ADAPTER_WINDOW` | 5 s | averaging window over `traffic-stats.csv` |

Outputs (in `$OUTDIR`):

- `traffic-stats.csv` — real measured per-backend pps
- `tx-stats.csv` — total TX pps from the generator
- `caps_schedule.json` — the applied schedule (copied in)
- `snapshot.json` — latest snapshot fed to the controller
- `snapshots.jsonl` — full adapter history, one JSON per cycle
- `alb.log`, `gen.log`, `col.log`, `adapter.log`, `llmgen.log`
- `convergence-real.png` — the final plot

Caveat: the synthetic capacity numbers in
[caps_schedule_default.json](test/caps_schedule_default.json) are
tuned for boxes pushing 6M+ aggregate pps (so the equal-split rate
exceeds the lowest cap and the controller sees non-zero miss). On
slower hosts, scale the schedule down by editing the JSON.

---

## 10. File map

```
packages/llm-strategy/
├── BUILD.bazel
├── PROMPT.md                          # original spec
├── FULL_README.md                     # this file
├── include/
│   └── metrics.hpp                    # MetricsCollector API
├── src/
│   ├── metrics.cpp                    # snapshot + JSON/CSV serialization
│   ├── stub_generator.hpp             # water-filling controller API
│   ├── stub_generator.cpp             # compute_weights() + emit_source()
│   ├── smoke_tester.cpp               # subprocess sandbox for candidate .so
│   └── generator.py                   # the actual loop (LLM driver + stub fallback)
└── test/
    ├── convergence_test.cpp           # cc_test + cc_binary (sim + assertions)
    ├── plot_convergence.py            # matplotlib driver
    ├── run_convergence_plot.sh        # rerunnable wrapper
    ├── stub_generator_test.sh         # sh_test for offline generator CLI path
    ├── convergence.csv                # generated (simulator)
    ├── markers.csv                    # generated (simulator)
    ├── convergence.png                # generated (simulator, committed)
    ├── metrics_adapter.py             # real-hw: collector CSV → snapshot.json
    ├── caps_schedule_default.json     # real-hw: default capacity schedule
    ├── run_4port_convergence.sh       # real-hw: orchestrator (sudo + DPDK)
    └── plot_4port_convergence.py      # real-hw: plot driver
```

Also touched (minimally, additively) in the rest of the repo:

- [packages/balancer-strategies/BUILD.bazel](../balancer-strategies/BUILD.bazel)
  — added a `filegroup(name = "strategy_hdr")` so llm-strategy's
  runtime consumers can reach `strategy.hpp` as a data dependency.
- [README.md](../../README.md) — two new rows in the test table,
  one new row in the packages table.
- [third_party/dpdk.bzl](../../third_party/dpdk.bzl) — unrelated DPDK
  fix: rewrites pkg-config's system `-I` flags as `-isystem` and
  filters out transitive `libnl`/`dbus` paths that Bazel's sandbox
  won't accept. Fixes `bazel test //...` on hosts where pkg-config
  emits absolute system paths.

---

## 11. Caveats and known gaps

- **The LLM can burn tokens**. Every cycle is a full API call with
  `max_tokens=4096`. Prompt caching reduces input cost for the ABI
  and system prompt, but generated output is always uncached.
  Running against live traffic at 5-second intervals costs real
  money. Set `--stub` unless you're actively exercising the LLM
  path.
- **Generated source trust boundary is subprocess-only**. We don't
  sandbox with seccomp, namespaces, or resource limits beyond the
  10-second timeout in the smoke tester. A maliciously crafted
  `.so` could still do bad things inside the smoke-tester process
  for 10 s (e.g. fork, eat CPU). Fine for trusted LLM output;
  harden before exposing to untrusted inputs.
- **Convergence test uses the direct HotSwapTable path**, not the
  full compile+inotify+dlopen path. The compile path is exercised
  by `llm_generator_stub_test` separately, and the inotify path is
  exercised by the pre-existing `alb_strategy_reload_test`. Every
  individual hop is tested; there's no single end-to-end test that
  exercises all of them in one binary. (It would be slow and
  flaky — the hot-swap needs a running DPDK worker loop to have
  something to reload into.)
- **3000 pps is synthetic**. The real ALB runs at line rate — many
  orders of magnitude above this. The convergence test is not a
  performance test; it's a behavior test for the controller
  algorithm.
- **No per-flow stickiness**. The underlying strategy is a
  stateless weighted hash. If a future strategy wants session
  affinity, the ABI already carries `packet_hash` (currently
  `src_ip ^ dst_ip` per `strategy_loader.cpp`), so a strategy can
  bucket by hash without change to the ABI.
- **Python path in Bazel**. `py_binary` targets are tagged
  `manual` because they rely on the system Python having
  `anthropic` / `matplotlib` installed. If you vendorize these
  via `rules_python` + `pip`, drop the `manual` tag.
