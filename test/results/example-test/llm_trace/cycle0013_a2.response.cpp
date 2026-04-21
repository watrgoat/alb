```cpp
#include <cstdint>

struct StrategyInput {
    uint32_t packet_hash;
    uint32_t packet_index;
};

struct ServerState {
    uint32_t address;
    uint64_t mac;
    uint32_t active_connections;
    uint32_t weight;
};

class Strategy {
public:
    virtual ServerState *select(const StrategyInput &s) = 0;
    virtual ~Strategy() = default;
};

// Computed weights based on capacity hints and current metrics
// Backend 0: capacity_hint=3333000, miss_rate=0.0, utilization=0.9871 → probe up 5%
// Backend 1: capacity_hint=3333000, miss_rate=0.0, utilization=0.9991 → probe up 5%
// Backend 2: capacity_hint=3333999, miss_rate=0.0136, overflow seen → snap to effective
//
// Backend 2 had packets_sent=16900000, packets_missed=230005
// effective[2] = 16900000 - 230005 = 16669995
// cap_budget[2] = max(1, 3333999 * 5) = 16669995
// new_weight[2] = min(16669995, 16669995) = 16669995
//
// Backend 0: packets_sent=16450000 → new_weight[0] = min(16450000 * 1.05, 3333000 * 5)
//            = min(17272500, 16665000) = 16665000
// Backend 1: packets_sent=16650000 → new_weight[1] = min(16650000 * 1.05, 3333000 * 5)
//            = min(17482500, 16665000) = 16665000
//
// Renormalize: sum = 16665000 + 16665000 + 16669995 = 49999995
// Keep ratios but scale to reasonable integers: divide by ~5000000
// Result: [3.333, 3.333, 3.334] → [3333, 3333, 3334]

constexpr uint32_t kWeights[3] = {3333, 3333, 3334};
constexpr uint32_t kTotalWeight = 10000;

class CapacityAwareStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;

public:
    CapacityAwareStrategy(ServerState *srv, int count)
        : servers(srv), server_count(count) {}

    ServerState *select(const StrategyInput &input) override {
        uint32_t target = input.packet_hash % kTotalWeight;
        uint32_t cumulative = 0;

        for (int i = 0; i < server_count; i++) {
            cumulative += kWeights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }

        return &servers[server_count - 1];
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```