# balancer-strategies

Pluggable load balancing strategy interface. Strategies are shared libraries hot-swapped at runtime via `dlopen`.

## Available Strategies

| Strategy | Description |
|----------|-------------|
| `libteststrategy.so` | Round-robin (cycles through servers) |
| `libweightedstrategy.so` | Weighted (distributes by server weight) |

## Build

```bash
bazel build //packages/balancer-strategies:libweightedstrategy.so
```

## Test

```bash
bazel test //packages/balancer-strategies:strategy_test
```

## Implement a Strategy

```cpp
#include "strategy.hpp"

class MyStrategy : public Strategy {
    ServerState* select(const StrategyInput& s) override { /* ... */ }
};

extern "C" Strategy* create_strategy(ServerState* servers, int count);
extern "C" void destroy_strategy(Strategy* s);
```
