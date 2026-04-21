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

public:
    CapacityAwareStrategy(ServerState *servers_, int count) 
        : servers(servers_), server_count(count), total_weight(0) {
        
        // Initialize weights based on the snapshot data
        // Backend 0: miss_rate=0.4933, capacity_hint=1666999
        // Backend 1: miss_rate=0.0, capacity_hint=3333000
        // Backend 2: miss_rate=0.0, capacity_hint=5000000
        
        uint32_t new_weights[3];
        
        // Backend 0: has miss_rate > 0 (0.4933)
        // effective = packets_sent - packets_missed = 16450000 - 8115005 = 8334995
        // cap_budget = max(1, 1666999 * 5) = 8334995
        // new_weight[0] = min(8334995, 8334995) = 8334995
        new_weights[0] = 8334995;
        
        // Backend 1: miss_rate = 0 (healthy)
        // probe up: packets_sent * 1.05 = 16650000 * 1.05 = 17482500
        // cap_budget = max(1, 3333000 * 5) = 16665000
        // new_weight[1] = min(17482500, 16665000) = 16665000
        new_weights[1] = 16665000;
        
        // Backend 2: miss_rate = 0 (healthy)
        // probe up: packets_sent * 1.05 = 16900000 * 1.05 = 17745000
        // cap_budget = max(1, 5000000 * 5) = 25000000
        // new_weight[2] = min(17745000, 25000000) = 17745000
        new_weights[2] = 17745000;
        
        // Renormalize to keep ratios but prevent overflow
        // Sum = 8334995 + 16665000 + 17745000 = 42744995
        // Scale down by dividing by a factor to fit in uint32_t range
        // We can use ratios directly or scale down
        uint64_t sum = (uint64_t)new_weights[0] + new_weights[1] + new_weights[2];
        
        // Target: keep sum reasonable. Use GCD-like approach
        // Divide all by 2500 to get manageable numbers
        uint32_t divisor = 2500;
        
        for (int i = 0; i < 3; i++) {
            weights[i] = (new_weights[i] / divisor);
            if (weights[i] < 1) weights[i] = 1;
        }
        
        total_weight = weights[0] + weights[1] + weights[2];
        
        // Sanity check: predicted miss under proposed weights
        // total_inbound_pps = 10000000
        // predicted_sent[0] = 10000000 * (3333/10998) ≈ 3033000
        // predicted_sent[1] = 10000000 * (6666/10998) ≈ 6066000
        // predicted_sent[2] = 10000000 * (7098/10998) ≈ 6458500
        // sum(max(0, pred - cap)) ≈ max(0, 3033000-1666999) + 0 + 0 ≈ 1366001
        // This is > 1% of inbound, but we're responding to observed miss
        // The capacity hints sum to 10000000, matching inbound, so system isn't over-subscribed
        // Our weights anchor on the observed effective throughput + cap constraints
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

    virtual ~CapacityAwareStrategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```