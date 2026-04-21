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
        compute_weights();
    }

    void compute_weights() {
        const uint32_t window_sec = 5;
        const uint32_t total_inbound_pps = 10000000;
        
        // Backend metrics from snapshot
        uint32_t packets_sent[3] = {16450000, 16650000, 16900000};
        uint32_t packets_missed[3] = {0, 0, 230005};
        uint32_t capacity_hint[3] = {3333000, 3333000, 3333999};
        
        uint32_t new_weight[3];
        
        for (int i = 0; i < 3; i++) {
            uint32_t cap_budget = (capacity_hint[i] > 0) 
                ? capacity_hint[i] * window_sec 
                : 1;
            
            if (packets_missed[i] > 0) {
                // Backend is overflowing: use stricter of effective or cap_budget
                uint32_t effective = packets_sent[i] - packets_missed[i];
                new_weight[i] = (effective < cap_budget) ? effective : cap_budget;
                if (new_weight[i] < 1) new_weight[i] = 1;
            } else {
                // Healthy: probe up gently (5%), never exceed cap
                uint32_t probed = packets_sent[i] + (packets_sent[i] / 20);
                new_weight[i] = (probed < cap_budget) ? probed : cap_budget;
                if (new_weight[i] < 1) new_weight[i] = 1;
            }
        }
        
        // Renormalize to preserve ratios while keeping sum reasonable
        uint32_t sum = new_weight[0] + new_weight[1] + new_weight[2];
        if (sum == 0) sum = 1;
        
        // Scale down if too large, keeping ratios
        const uint32_t max_total = 10000;
        if (sum > max_total) {
            uint32_t gcd_val = gcd(gcd(new_weight[0], new_weight[1]), new_weight[2]);
            if (gcd_val < 1) gcd_val = 1;
            new_weight[0] /= gcd_val;
            new_weight[1] /= gcd_val;
            new_weight[2] /= gcd_val;
            sum = new_weight[0] + new_weight[1] + new_weight[2];
            if (sum == 0) sum = 1;
        }
        
        // Ensure all weights >= 1
        for (int i = 0; i < 3; i++) {
            if (new_weight[i] < 1) new_weight[i] = 1;
        }
        
        weights[0] = new_weight[0];
        weights[1] = new_weight[1];
        weights[2] = new_weight[2];
        total_weight = weights[0] + weights[1] + weights[2];
        
        if (total_weight == 0) total_weight = 1;
    }

    static uint32_t gcd(uint32_t a, uint32_t b) {
        while (b != 0) {
            uint32_t temp = b;
            b = a % b;
            a = temp;
        }
        return (a > 0) ? a : 1;
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
        
        return &servers[0];
    }

    ~CapacityAwareStrategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```