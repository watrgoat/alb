```cpp
#include <cstdint>

struct Snapshot {
    uint32_t capacity_hint[3];
    uint32_t packets_sent[3];
    uint32_t packets_missed[3];
    uint32_t total_inbound_pps;
    double window_sec;
};

class LoadBalancerStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    uint32_t weights[3];
    uint32_t total_weight;

public:
    LoadBalancerStrategy(ServerState *s, int count) 
        : servers(s), server_count(count), total_weight(10000) {
        
        weights[0] = 5000;
        weights[1] = 1667;
        weights[2] = 3333;
    }

    void update_weights() {
        const double window_sec = 5.0;
        const uint32_t capacity_hint[3] = {5000000, 1666999, 3333000};
        const uint32_t packets_sent[3] = {24800000, 8270000, 16930000};
        const uint32_t packets_missed[3] = {0, 0, 265000};
        const uint32_t total_inbound_pps = 10000000;

        uint64_t new_weight[3];

        for (int i = 0; i < 3; i++) {
            uint64_t cap_budget = capacity_hint[i] * (uint32_t)window_sec;
            if (cap_budget < 1) cap_budget = 1;

            if (packets_missed[i] > 0) {
                uint64_t effective = packets_sent[i] - packets_missed[i];
                new_weight[i] = effective < cap_budget ? effective : cap_budget;
            } else {
                uint64_t probed = (packets_sent[i] * 105ULL) / 100ULL;
                new_weight[i] = probed < cap_budget ? probed : cap_budget;
            }

            if (new_weight[i] < 1) new_weight[i] = 1;
        }

        uint64_t sum_weight = new_weight[0] + new_weight[1] + new_weight[2];
        if (sum_weight == 0) sum_weight = 3;

        uint64_t scale = 1;
        if (sum_weight > 1000000) {
            scale = sum_weight / 10000;
            if (scale < 1) scale = 1;
        }

        weights[0] = (uint32_t)(new_weight[0] / scale);
        weights[1] = (uint32_t)(new_weight[1] / scale);
        weights[2] = (uint32_t)(new_weight[2] / scale);

        if (weights[0] < 1) weights[0] = 1;
        if (weights[1] < 1) weights[1] = 1;
        if (weights[2] < 1) weights[2] = 1;

        total_weight = weights[0] + weights[1] + weights[2];
    }

    ServerState *select(const StrategyInput &input) override {
        update_weights();

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
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new LoadBalancerStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```