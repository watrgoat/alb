# balancer-strategies

Pluggable load balancing strategy interface. Strategies are compiled as shared libraries and can be hot-swapped at runtime via `dlopen`.

## Build Strategy

```bash
g++ -shared -fPIC -o build/libteststrategy.so strategies/test-strategy-impl.cpp -I include
```

## Build & Run Tests

```bash
g++ -o build/test_main test/main.cpp -I include -ldl
./build/test_main
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
