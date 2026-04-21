# LLM Strategy Generator — Implementation Prompt

Implement an LLM-driven strategy generator for this ALB project. The generator
observes live backend metrics, asks an LLM to write a new load-balancing
algorithm, compiles it to a shared object, and drops it into the
hot-swap-watched directory so the running ALB picks it up without restart.
Then prove it works with a convergence test.

## What already exists (read these before writing anything)

- [packages/balancer-strategies/include/strategy.hpp](../balancer-strategies/include/strategy.hpp) —
  the `Strategy` ABI: `select(const StrategyInput&)`, `ServerState`,
  `create_strategy` / `destroy_strategy` C entrypoints.
- [packages/balancer-strategies/strategies/](../balancer-strategies/strategies/) —
  reference implementations (`test-strategy-impl.cpp`, `weighted-strategy-impl.cpp`).
- [packages/version-table/include/table.hpp](../version-table/include/table.hpp) —
  `HotSwapTable` / `Slot` with in-flight refcounting.
- [src/strategy_loader.cpp](../../src/strategy_loader.cpp) —
  `manager_main` inotifies `./strategies/` for `libstrategy.so`, loads via
  `dlopen`, swaps the active slot, drains the old slot, `dlclose`s it.
- [src/strategy_loader.hpp](../../src/strategy_loader.hpp) — `StrategySlotData`,
  `worker_main`, `BURST_SIZE`.
- [traffic-stats.csv](../../traffic-stats.csv) — sample metric shape:
  `timestamp,ip,packets_delta` sampled every ~5s.

**Do not** break the existing ABI. Any generated strategy must export
`create_strategy(ServerState*, int)` and `destroy_strategy(Strategy*)` with
C linkage, return a `Strategy*`, and never allocate across the slot boundary.

## Deliverables

### 1. Metrics collector (`packages/llm-strategy/src/metrics.{hpp,cpp}`)

- Per-backend rolling window of:
  - `packets_sent` (from ALB TX path — hook `worker_main` after the
    successful `rte_eth_tx_burst`, bucket by `bidx`).
  - `packets_missed` (backend-reported drops — simulated in tests, see §3).
  - `active_connections` (already tracked on `ServerState`).
- Emit a snapshot every N seconds as a plain struct the prompt builder can
  serialize to JSON. Same schema as `traffic-stats.csv` plus `missed` and
  `capacity_hint` columns.
- Keep this header-only or under a single `cc_library` — no new third-party
  deps beyond what's already in `MODULE.bazel`.

### 2. LLM generator loop (`packages/llm-strategy/src/generator.{hpp,cpp}` + a CLI)

The loop:

1. Read a metrics snapshot.
2. Build a prompt containing (a) the `Strategy` ABI from `strategy.hpp`
   verbatim, (b) the last snapshot, (c) the last N generated strategies'
   source + their resulting miss rates (so the model can learn from its
   own history), (d) the target: **minimize `sum(packets_missed)` while
   keeping throughput within 5% of current**.
3. Call the Claude API (Anthropic SDK, model `claude-opus-4-7` by default,
   configurable via env). Use prompt caching on the ABI + history prefix.
   Ask the model to return a single C++ file implementing `Strategy`,
   `create_strategy`, `destroy_strategy`. Constrain output with a system
   prompt that forbids I/O, threads, globals with non-trivial destructors,
   and anything outside the ABI.
4. Write the returned source to a temp file, compile with the same flags
   Bazel uses for the reference strategies (`-fPIC -shared -O2
   -std=c++17`). On compile failure, feed the diagnostic back into the
   next prompt as "previous attempt failed because …" and retry up to 3
   times before giving up on this cycle.
5. Atomically move the built `.so` into `./strategies/libstrategy.so`
   (write to `./strategies/.libstrategy.so.tmp`, `rename(2)` — inotify
   fires on `IN_MOVED_TO`, which `manager_main` already watches).
6. After the swap, wait one metrics window, then score the new strategy by
   its miss rate. Store `(source, score)` in the history buffer for step 2.

The loop must be interruptible (SIGINT → flush history → exit cleanly) and
must not swap in a strategy that failed to compile or failed a quick
in-process smoke test (`create_strategy` returns non-null, 100 `select()`
calls don't segfault and return pointers within the `servers` array).

Credentials: read `ANTHROPIC_API_KEY` from env; if unset, fall back to a
deterministic stub generator that emits a weighted-least-connections
strategy so the test suite doesn't require network access.

### 3. Convergence test (`packages/llm-strategy/test/convergence_test.{cpp,py}`)

This is the headline demo. It must produce a graph showing the system
learning.

**Harness:**

- 3 simulated backends. Each has a configurable `processing_capacity_pps`
  (packets per second it can serve before dropping). Simulate in-process —
  no real DPDK needed for this test. The "backend" is a function that,
  given the per-second inbound rate, returns
  `missed = max(0, inbound - capacity)`.
- Traffic generator runs at a fixed aggregate rate (e.g., 300 pps total).
- The ALB routing decision uses the current `Strategy` from the hot-swap
  table. Plug the generator loop from §2 into this harness so it rewrites
  the active strategy every K seconds using the same inotify path (or a
  direct `HotSwapTable::swap` for the unit test — both paths must work).

**Scenario:**

1. Start with backends at capacities `[100, 100, 100]` pps. Expected
   steady-state miss rate with even routing: 0.
2. At t=30s, change capacities to `[50, 100, 150]`. Naive round-robin now
   drops ~50 pps at backend 0. The LLM loop should converge routing
   weights toward `[1, 2, 3]` (or equivalent) within a few cycles.
3. At t=90s, change to `[150, 50, 100]`. Convergence should happen again.
4. At t=150s, change to `[100, 100, 100]`. Back to even.

**Plot:**

- X axis: time (s).
- Y axis: pps.
- One line per backend for `packets_sent`.
- One line per backend for `packets_missed` (dashed).
- One horizontal line per backend for `processing_capacity_pps` (the
  target each `packets_sent` line should converge toward).
- Vertical markers at each capacity change.

Render with matplotlib from the Python side — the C++ test writes a CSV
(reuse the `traffic-stats.csv` schema plus `missed` and `capacity`
columns), and the Python driver plots it. Save to
`packages/llm-strategy/test/convergence.png` and assert that within 20s
after each capacity change, `packets_sent[i] / capacity[i]` is within
`[0.9, 1.1]` for every backend, and `sum(missed)` is under 5% of total
inbound.

### 4. Bazel + test integration

- Add `packages/llm-strategy/BUILD.bazel` with:
  - `cc_library` for metrics + generator.
  - `cc_binary` for the generator CLI.
  - `cc_test` for the in-process convergence test (uses the stub generator
    so it runs offline and in CI).
  - `py_binary` for the plot driver (tagged `manual` if matplotlib isn't
    already a dep; otherwise wire it in).
- Add to the table in [README.md](../../README.md):
  `llm_convergence_test | LLM-driven strategy convergence under shifting backend capacity`.
- The existing `swap_test` and `strategy_test` must still pass unchanged —
  this is additive. Run `bazel test //...` and confirm before finishing.

## Constraints

- No changes to the `Strategy` ABI or to `HotSwapTable`. If you find
  yourself wanting to, stop and explain why in the PR description instead.
- The LLM call is the only network I/O. Everything else is local.
- Generated code is untrusted — never execute it in the generator
  process's address space before the smoke test passes. Compile to `.so`,
  load it in a subprocess or a forked child for the smoke test, only then
  promote it to `./strategies/libstrategy.so`.
- Keep the prompt under 8k tokens. The history buffer should cap at the
  last 3 attempts — older ones are summarized as `(miss_rate, one-line
  description)` only.

## Done criteria

1. `bazel test //...` green, including the new `llm_convergence_test`.
2. `packages/llm-strategy/test/convergence.png` checked in (or regenerable
   with a single `bazel run` command) and visibly shows each `packets_sent`
   line tracking its capacity line after each shift.
3. Running `bazel-bin/packages/llm-strategy/generator` against a live ALB
   (with `ANTHROPIC_API_KEY` set) produces real `.so` swaps logged by
   `manager_main`'s existing `"reload complete"` message.
