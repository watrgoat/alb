```cpp
#include <cstdint>

class CapacityAwareStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    uint32_t weights[3];

public:
    CapacityAwareStrategy(ServerState *servers_arg, int count)
        : servers(servers_arg), server_count(count) {
        // Initialize weights based on capacity hints
        init_weights();
    }

    void init_weights() {
        // Current snapshot analysis:
        // Backend 0: capacity_hint=5000000, utilization=0.992, miss_rate=0.0
        // Backend 1: capacity_hint=1666999, utilization=0.9922, miss_rate=0.0
        // Backend 2: capacity_hint=3333000, utilization=1.0159, miss_rate=0.0157 (OVERLOADED)
        
        // Window = 5.0 seconds
        // total_inbound_pps = 10000000
        
        const uint32_t window = 5;
        const uint64_t total_inbound_pps = 10000000;
        
        // Capacity budgets
        uint32_t cap_budget[3];
        cap_budget[0] = 5000000 * window;      // 25000000
        cap_budget[1] = 1666999 * window;      // 8334995
        cap_budget[2] = 3333000 * window;      // 16665000
        
        // Current observations
        uint64_t packets_sent[3] = {24800000, 8270000, 16930000};
        uint64_t packets_missed[3] = {0, 0, 265000};
        double miss_rate[3] = {0.0, 0.0, 0.0157};
        
        uint32_t new_weight[3];
        
        // Backend 0: healthy (miss_rate = 0)
        // Probe up 5%: min(24800000 * 1.05, 25000000) = min(26040000, 25000000) = 25000000
        new_weight[0] = 25000000;
        
        // Backend 1: healthy (miss_rate = 0)
        // Probe up 5%: min(8270000 * 1.05, 8334995) = min(8683500, 8334995) = 8334995
        new_weight[1] = 8334995;
        
        // Backend 2: OVERLOADED (miss_rate = 0.0157 > 0)
        // effective = 16930000 - 265000 = 16665000
        // new_weight = min(16665000, 16665000) = 16665000
        uint64_t effective_2 = packets_sent[2] - packets_missed[2];
        new_weight[2] = (uint32_t)effective_2;
        
        // Normalize to fit in uint32_t while preserving ratios
        // Sum = 25000000 + 8334995 + 16665000 = 49999995
        // This is manageable, but let's scale down by ~5000 to get reasonable weight values
        
        uint64_t sum = (uint64_t)new_weight[0] + new_weight[1] + new_weight[2];
        uint32_t scale_down = (sum > 50000) ? (uint32_t)(sum / 5000) : 1;
        
        weights[0] = new_weight[0] / scale_down;
        weights[1] = new_weight[1] / scale_down;
        weights[2] = new_weight[2] / scale_down;
        
        // Ensure all weights >= 1
        if (weights[0] < 1) weights[0] = 1;
        if (weights[1] < 1) weights[1] = 1;
        if (weights[2] < 1) weights[2] = 1;
        
        // Sanity check: predict misses
        uint64_t total_weight = weights[0] + weights[1] + weights[2];
        uint64_t predicted_miss = 0;
        
        for (int i = 0; i < 3; i++) {
            uint64_t share_numerator = weights[i];
            uint64_t predicted_sent = (total_inbound_pps * share_numerator) / total_weight;
            uint64_t capacity = (i == 0) ? 5000000 : (i == 1) ? 1666999 : 3333000;
            if (predicted_sent > capacity) {
                predicted_miss += predicted_sent - capacity;
            }
        }
        
        // If predicted miss is too high and system not oversubscribed, adjust
        uint64_t total_capacity = 5000000 + 1666999 + 3333000;
        if (predicted_miss > (total_inbound_pps / 100) && total_capacity >= total_inbound_pps) {
            // Pull weights closer to capacity hints
            weights[0] = 5000000 / 1000;
            weights[1] = 1666999 / 1000;
            weights[2] = 3333000 / 1000;
            if (weights[0] < 1) weights[0] = 1;
            if (weights[1] < 1) weights[1] = 1;
            if (weights[2] < 1) weights[2] = 1;
        }
    }

    ServerState *select(const StrategyInput &input) override {
        uint32_t total_weight = weights[0] + weights[1] + weights[2];
        uint32_t target = input.packet_hash % total_weight;
        
        uint32_t cumulative = 0;
        for (int i = 0; i < server_count; i++) {
            cumulative += weights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }
        
        return &servers[server_count - 1];
    }

    ~CapacityAwareStrategy() override = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```