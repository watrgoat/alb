```cpp
#include <cstdint>

struct Snapshot {
    uint32_t packets_sent[3];
    uint32_t packets_missed[3];
    uint32_t capacity_hint[3];
    uint32_t total_inbound_pps;
    double window_sec;
};

class CapacityAwareStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    uint32_t weights[3];
    uint32_t total_weight;

    void compute_weights() {
        const Snapshot snap = {
            {16550000, 16355000, 17095000},
            {0, 0, 425005},
            {3333000, 3333000, 3333999},
            10000000,
            5.0
        };

        uint32_t new_weight[3];
        double window = snap.window_sec;

        for (int i = 0; i < 3; i++) {
            uint32_t cap_budget = (uint32_t)(snap.capacity_hint[i] * window);
            if (cap_budget < 1) cap_budget = 1;

            if (snap.packets_missed[i] > 0) {
                uint32_t effective = snap.packets_sent[i] - snap.packets_missed[i];
                new_weight[i] = effective < cap_budget ? effective : cap_budget;
            } else {
                uint64_t probed = (uint64_t)snap.packets_sent[i] * 105 / 100;
                new_weight[i] = probed > cap_budget ? cap_budget : (uint32_t)probed;
            }

            if (new_weight[i] < 1) new_weight[i] = 1;
        }

        uint32_t sum = new_weight[0] + new_weight[1] + new_weight[2];
        if (sum == 0) sum = 1;

        double scale = 10000.0 / sum;
        uint32_t scaled[3];
        for (int i = 0; i < 3; i++) {
            scaled[i] = (uint32_t)(new_weight[i] * scale);
            if (scaled[i] < 1) scaled[i] = 1;
        }

        weights[0] = scaled[0];
        weights[1] = scaled[1];
        weights[2] = scaled[2];
        total_weight = weights[0] + weights[1] + weights[2];
    }

public:
    CapacityAwareStrategy(ServerState *srv, int cnt) 
        : servers(srv), server_count(cnt), total_weight(0) {
        compute_weights();
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
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```