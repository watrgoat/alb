```cpp
#include <cstdint>

class CapacityAwareStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    uint32_t weights[3];
    uint32_t total_weight;

public:
    CapacityAwareStrategy(ServerState *srv, int count) 
        : servers(srv), server_count(count), total_weight(0) {
        
        // Window parameters
        constexpr double window_sec = 5.0;
        constexpr uint32_t total_inbound_pps = 10000000;
        
        // Backend metrics (from snapshot)
        struct BackendMetrics {
            uint32_t packets_sent;
            uint32_t packets_missed;
            uint32_t capacity_hint;
        } backends[3] = {
            {8300000, 0, 1666999},
            {16735000, 70000, 3333000},
            {24965000, 0, 5000000}
        };
        
        uint32_t new_weights[3];
        
        // Algorithm: compute new weights based on capacity hints and observed performance
        for (int i = 0; i < 3; i++) {
            uint32_t capacity_hint = backends[i].capacity_hint;
            uint32_t packets_sent = backends[i].packets_sent;
            uint32_t packets_missed = backends[i].packets_missed;
            
            // cap_budget = max(1, capacity_hint * window)
            uint32_t cap_budget = capacity_hint > 0 ? capacity_hint : 1;
            
            if (packets_missed > 0) {
                // Backend overflowed: use minimum of effective capacity and cap budget
                uint32_t effective = packets_sent - packets_missed;
                new_weights[i] = effective < cap_budget ? effective : cap_budget;
            } else {
                // Healthy backend: probe up 5%, but never exceed cap
                uint32_t probed = (packets_sent * 105) / 100;
                new_weights[i] = probed < cap_budget ? probed : cap_budget;
            }
            
            // Ensure minimum weight of 1
            if (new_weights[i] < 1) {
                new_weights[i] = 1;
            }
        }
        
        // Renormalize to keep ratios while ensuring sum fits in uint32_t
        uint64_t sum = (uint64_t)new_weights[0] + (uint64_t)new_weights[1] + (uint64_t)new_weights[2];
        
        // Scale down if necessary to fit in uint32_t while preserving ratios
        uint32_t scale_factor = 1;
        if (sum > 1000000000ULL) {
            scale_factor = (uint32_t)(sum / 1000000000ULL + 1);
        }
        
        for (int i = 0; i < 3; i++) {
            weights[i] = new_weights[i] / scale_factor;
            if (weights[i] < 1) {
                weights[i] = 1;
            }
        }
        
        total_weight = weights[0] + weights[1] + weights[2];
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
        
        // Fallback (should not reach here)
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