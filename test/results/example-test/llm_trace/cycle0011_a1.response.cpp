```cpp
#include <cstdint>

class CapacityAwareStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    uint32_t weights[3];
    uint32_t total_weight;

public:
    CapacityAwareStrategy(ServerState *servers_, int count) 
        : servers(servers_), server_count(count) {
        compute_weights();
    }

    void compute_weights() {
        // Window parameters
        const double window_sec = 5.0;
        const uint32_t total_inbound_pps = 10000000;
        
        // Backend data from snapshot
        struct BackendData {
            uint32_t packets_sent;
            uint32_t packets_missed;
            uint32_t capacity_hint;
        } backends[3] = {
            {24865000, 8200000, 3333000},
            {7965000, 0, 3333000},
            {17170000, 500005, 3333999}
        };

        uint32_t new_weight[3];
        uint32_t sum_weight = 0;

        // Step 1: Compute raw weights based on algorithm
        for (int i = 0; i < 3; i++) {
            uint32_t cap_budget = (uint32_t)(backends[i].capacity_hint * window_sec);
            if (cap_budget < 1) cap_budget = 1;

            if (backends[i].packets_missed > 0) {
                // Overloaded: snap to effective throughput or capacity budget
                uint32_t effective = backends[i].packets_sent - backends[i].packets_missed;
                new_weight[i] = effective < cap_budget ? effective : cap_budget;
            } else {
                // Healthy: probe up gently (5%), but never exceed cap
                uint32_t probed = (uint32_t)(backends[i].packets_sent * 1.05);
                new_weight[i] = probed < cap_budget ? probed : cap_budget;
            }

            // Ensure minimum weight of 1
            if (new_weight[i] < 1) new_weight[i] = 1;
            sum_weight += new_weight[i];
        }

        // Step 2: Sanity check and adjust if needed
        // Compute predicted miss under proposed weights
        double predicted_miss_pps = 0.0;
        for (int i = 0; i < 3; i++) {
            double share = (double)new_weight[i] / (double)sum_weight;
            double predicted_sent = total_inbound_pps * share;
            double excess = predicted_sent - backends[i].capacity_hint;
            if (excess > 0) {
                predicted_miss_pps += excess;
            }
        }

        // Check if adjustment is needed
        double miss_threshold = 0.01 * total_inbound_pps;
        uint32_t total_capacity = backends[0].capacity_hint + 
                                  backends[1].capacity_hint + 
                                  backends[2].capacity_hint;
        
        if (predicted_miss_pps > miss_threshold && total_capacity >= total_inbound_pps) {
            // System not over-subscribed but we're predicting misses
            // Pull weights closer to capacity_hint ratios
            sum_weight = 0;
            for (int i = 0; i < 3; i++) {
                new_weight[i] = backends[i].capacity_hint;
                if (new_weight[i] < 1) new_weight[i] = 1;
                sum_weight += new_weight[i];
            }
        }

        // Step 3: Normalize to fit in uint32_t while preserving ratios
        // Use GCD-based reduction if sum is too large
        if (sum_weight > 10000000) {
            uint32_t divisor = sum_weight / 10000000;
            if (divisor > 0) {
                for (int i = 0; i < 3; i++) {
                    new_weight[i] = (new_weight[i] / divisor);
                    if (new_weight[i] < 1) new_weight[i] = 1;
                }
                sum_weight = new_weight[0] + new_weight[1] + new_weight[2];
            }
        }

        // Ensure all weights are at least 1
        for (int i = 0; i < 3; i++) {
            if (new_weight[i] < 1) new_weight[i] = 1;
        }
        sum_weight = new_weight[0] + new_weight[1] + new_weight[2];

        // Store computed weights
        weights[0] = new_weight[0];
        weights[1] = new_weight[1];
        weights[2] = new_weight[2];
        total_weight = sum_weight;
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

    ~CapacityAwareStrategy() override = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```