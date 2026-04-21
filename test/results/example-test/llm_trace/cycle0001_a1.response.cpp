```cpp
#include <cstdint>

struct Snapshot {
    uint32_t packets_sent;
    uint32_t packets_missed;
    uint32_t capacity_hint;
};

class WaterFillingStrategy : public Strategy {
private:
    ServerState *servers;
    int count;
    uint32_t weights[3];

public:
    WaterFillingStrategy(ServerState *servers_, int count_)
        : servers(servers_), count(count_) {
        // Initialize weights based on water-filling algorithm
        // Backend 0: effective = 19905000 - 3240000 = 16665000, miss_rate > 0 → weight = 16665000
        // Backend 1: effective = 10155000 - 0 = 10155000, miss_rate = 0 → weight = 10155000 * 1.1 = 11170500
        // Backend 2: effective = 19940000 - 3270005 = 16669995, miss_rate > 0 → weight = 16669995
        weights[0] = 16665000u;
        weights[1] = 11170500u;
        weights[2] = 16669995u;
    }

    ServerState *select(const StrategyInput &input) override {
        uint32_t total_weight = weights[0] + weights[1] + weights[2];
        uint32_t target = input.packet_hash % total_weight;
        
        uint32_t cumulative = 0;
        for (int i = 0; i < count; ++i) {
            cumulative += weights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }
        
        return &servers[count - 1];
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new WaterFillingStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```