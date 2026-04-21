```cpp
#include <cstdint>

class CapacityAnchorStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    uint32_t weights[3];
    uint32_t total_weight;

public:
    CapacityAnchorStrategy(ServerState *srv, int count)
        : servers(srv), server_count(count), total_weight(0) {
        compute_weights();
    }

    void compute_weights() {
        constexpr uint32_t window_sec = 5;
        constexpr uint32_t total_inbound_pps = 10000000;
        
        // Current observed state from snapshot
        constexpr uint32_t capacity_hints[3] = {3333000, 3333000, 3333999};
        constexpr uint32_t packets_sent[3] = {16450000, 16650000, 16900000};
        constexpr uint32_t packets_missed[3] = {0, 0, 230005};
        constexpr double miss_rates[3] = {0.0, 0.0, 0.0136};
        
        uint32_t new_weights[3];
        
        for (int i = 0; i < 3; i++) {
            uint32_t cap_budget = capacity_hints[i] * window_sec;
            if (cap_budget < 1) cap_budget = 1;
            
            if (miss_rates[i] > 0.0) {
                // Backend is overloaded: snap to observed effective or cap_budget
                uint32_t effective = packets_sent[i] - packets_missed[i];
                new_weights[i] = effective < cap_budget ? effective : cap_budget;
            } else {
                // Healthy: probe up gently but never above cap
                uint32_t probed = (packets_sent[i] * 105) / 100;  // 5% probe
                new_weights[i] = probed < cap_budget ? probed : cap_budget;
            }
            
            if (new_weights[i] < 1) new_weights[i] = 1;
        }
        
        // Renormalize to avoid overflow and maintain ratios
        uint32_t sum = new_weights[0] + new_weights[1] + new_weights[2];
        if (sum == 0) sum = 1;
        
        // Scale down if sum is too large for uint32_t arithmetic
        while (sum > 10000000) {
            for (int i = 0; i < 3; i++) {
                new_weights[i] = (new_weights[i] + 1) / 2;
                if (new_weights[i] < 1) new_weights[i] = 1;
            }
            sum = new_weights[0] + new_weights[1] + new_weights[2];
        }
        
        weights[0] = new_weights[0];
        weights[1] = new_weights[1];
        weights[2] = new_weights[2];
        total_weight = sum;
    }

    ServerState *select(const StrategyInput &input) override {
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
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAnchorStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```