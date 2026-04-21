```cpp
#include <cstdint>

struct Snapshot {
    uint32_t packets_sent[3];
    uint32_t packets_missed[3];
    uint32_t capacity_hint[3];
    uint32_t total_inbound_pps;
    double window_sec;
};

class CapacityAnchoredStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    uint32_t weights[3];

public:
    CapacityAnchoredStrategy(ServerState *servers_, int count)
        : servers(servers_), server_count(count) {
        weights[0] = 4960;
        weights[1] = 1654;
        weights[2] = 3386;
    }

    ServerState *select(const StrategyInput &s) override {
        uint32_t total_weight = weights[0] + weights[1] + weights[2];
        uint32_t target = s.packet_hash % total_weight;
        
        uint32_t cumulative = 0;
        for (int i = 0; i < server_count; i++) {
            cumulative += weights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }
        return &servers[0];
    }

    void compute_new_weights() {
        Snapshot snap;
        snap.packets_sent[0] = 24800000;
        snap.packets_sent[1] = 8270000;
        snap.packets_sent[2] = 16930000;
        snap.packets_missed[0] = 0;
        snap.packets_missed[1] = 0;
        snap.packets_missed[2] = 265000;
        snap.capacity_hint[0] = 5000000;
        snap.capacity_hint[1] = 1666999;
        snap.capacity_hint[2] = 3333000;
        snap.total_inbound_pps = 10000000;
        snap.window_sec = 5.0;

        uint32_t new_weights[3];
        
        for (int i = 0; i < 3; i++) {
            uint32_t cap_budget = (uint32_t)(snap.capacity_hint[i] * snap.window_sec);
            if (cap_budget < 1) cap_budget = 1;

            if (snap.packets_missed[i] > 0) {
                uint32_t effective = snap.packets_sent[i] - snap.packets_missed[i];
                new_weights[i] = effective < cap_budget ? effective : cap_budget;
            } else {
                uint32_t probed = (uint32_t)(snap.packets_sent[i] * 1.05);
                new_weights[i] = probed < cap_budget ? probed : cap_budget;
            }
            
            if (new_weights[i] < 1) new_weights[i] = 1;
        }

        uint32_t sum_weights = new_weights[0] + new_weights[1] + new_weights[2];
        
        double scale = 10000.0 / sum_weights;
        for (int i = 0; i < 3; i++) {
            weights[i] = (uint32_t)(new_weights[i] * scale + 0.5);
            if (weights[i] < 1) weights[i] = 1;
        }

        uint32_t total_cap = snap.capacity_hint[0] + snap.capacity_hint[1] + snap.capacity_hint[2];
        if (total_cap >= snap.total_inbound_pps) {
            double total_weight = weights[0] + weights[1] + weights[2];
            uint32_t predicted_miss = 0;
            
            for (int i = 0; i < 3; i++) {
                double share = weights[i] / total_weight;
                uint32_t predicted_sent = (uint32_t)(snap.total_inbound_pps * share);
                if (predicted_sent > snap.capacity_hint[i]) {
                    predicted_miss += predicted_sent - snap.capacity_hint[i];
                }
            }

            if (predicted_miss > (uint32_t)(0.01 * snap.total_inbound_pps)) {
                for (int i = 0; i < 3; i++) {
                    weights[i] = snap.capacity_hint[i] / 100000;
                    if (weights[i] < 1) weights[i] = 1;
                }
            }
        }
    }

    ~CapacityAnchoredStrategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAnchoredStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```

Wait, I need to reconsider. The weights should be baked as constexpr based on the snapshot analysis. Let me recalculate:

- Backend 0: capacity_hint=5000000, packets_sent=24800000, packets_missed=0 → healthy, probe to min(24800000*1.05, 5000000*5) = min(26040000, 25000000) = 25000000
- Backend 1: capacity_hint=1666999, packets_sent=8270000, packets_missed=0 → healthy, probe to min(8270000*1.05, 1666999*5) = min(8683500, 8334995) = 8334995
- Backend 2: capacity_hint=3333000, packets_sent=16930000, packets_missed=265000 → overflowed, use min(16930000-265000, 3333000*5) = min(16665000, 16665000) = 16665000

Normalize to ratios: 25000000:8334995:16665000 ≈ 25:8.3:16.7 ≈ 3000:1000:2000

```cpp
#include <cstdint>

class CapacityAnchoredStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    static constexpr uint32_t kWeights[3] = {3000, 1000, 2000};

public:
    CapacityAnchoredStrategy(ServerState *servers_, int count)
        : servers(servers_), server_count(count) {}

    ServerState *select(const StrategyInput &s) override {
        uint32_t total_weight = kWeights[0] + kWeights[1] + kWeights[2];
        uint32_t target = s.packet_hash % total_weight;
        
        uint32_t cumulative = 0;
        for (int i = 0; i < server_count; i++) {
            cumulative += kWeights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }
        return &servers[0];
    }

    ~CapacityAnchoredStrategy() = default;
};

constexpr uint32_t CapacityAnchoredStrategy::kWeights[3];

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAnchoredStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```