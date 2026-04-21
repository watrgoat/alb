```cpp
#include <cstdint>

struct Strategy_Impl : public Strategy {
    ServerState *servers;
    int server_count;
    uint32_t weights[3];
    uint32_t total_weight;

    Strategy_Impl(ServerState *s, int count) : servers(s), server_count(count) {
        compute_weights();
    }

    void compute_weights() {
        const double window = 5.0;
        const double total_inbound_pps = 10000000.0;
        
        // Backend data from snapshot
        struct Backend {
            uint64_t packets_sent;
            uint64_t packets_missed;
            uint32_t capacity_hint;
            double miss_rate;
        } backends[3] = {
            {8260000, 0, 5000000, 0.0},
            {16845000, 8510005, 1666999, 0.5052},
            {24895000, 8230000, 3333000, 0.3306}
        };

        uint64_t new_weight[3];

        for (int i = 0; i < 3; ++i) {
            uint64_t cap_budget = (uint64_t)((double)backends[i].capacity_hint * window);
            if (cap_budget < 1) cap_budget = 1;

            if (backends[i].miss_rate > 0.0) {
                uint64_t effective = backends[i].packets_sent - backends[i].packets_missed;
                new_weight[i] = effective < cap_budget ? effective : cap_budget;
            } else {
                uint64_t probed = (uint64_t)((double)backends[i].packets_sent * 1.05);
                new_weight[i] = probed < cap_budget ? probed : cap_budget;
            }

            if (new_weight[i] < 1) new_weight[i] = 1;
        }

        uint64_t sum = new_weight[0] + new_weight[1] + new_weight[2];

        // Sanity check: predict miss rate under proposed weights
        double predicted_miss_pps = 0.0;
        bool system_over_subscribed = 
            (5000000 + 1666999 + 3333000) < total_inbound_pps;

        for (int i = 0; i < 3; ++i) {
            double share = (double)new_weight[i] / (double)sum;
            double predicted_sent = total_inbound_pps * share;
            double predicted_miss = predicted_sent - (double)backends[i].capacity_hint;
            if (predicted_miss > 0.0) {
                predicted_miss_pps += predicted_miss;
            }
        }

        if (predicted_miss_pps > 0.01 * total_inbound_pps && !system_over_subscribed) {
            // Weights are wrong — pull closer to capacity_hint ratios
            new_weight[0] = 5000000;
            new_weight[1] = 1666999;
            new_weight[2] = 3333000;
            sum = new_weight[0] + new_weight[1] + new_weight[2];
        }

        // Normalize to fit in uint32_t while preserving ratios
        uint64_t max_val = new_weight[0];
        if (new_weight[1] > max_val) max_val = new_weight[1];
        if (new_weight[2] > max_val) max_val = new_weight[2];

        double scale = 1.0;
        if (sum > 10000) {
            scale = 10000.0 / (double)sum;
        }

        for (int i = 0; i < 3; ++i) {
            weights[i] = (uint32_t)((double)new_weight[i] * scale);
            if (weights[i] < 1) weights[i] = 1;
        }

        total_weight = weights[0] + weights[1] + weights[2];
        if (total_weight < 1) total_weight = 1;
    }

    ServerState *select(const StrategyInput &input) override {
        uint32_t target = input.packet_hash % total_weight;
        uint32_t cumulative = 0;

        for (int i = 0; i < server_count; ++i) {
            cumulative += weights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }

        return &servers[server_count - 1];
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new Strategy_Impl(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```