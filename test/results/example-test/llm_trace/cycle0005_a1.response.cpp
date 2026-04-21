Looking at the snapshot and previous attempts, I need to apply the water-filling algorithm:

For each backend:
- If miss_rate > 0: new_weight = effective_packets = packets_sent - packets_missed
- If miss_rate = 0: new_weight = packets_sent * 1.1

From the snapshot:
- Backend 0: effective = 10165000 - 1830005 = 8334995, miss_rate=0.18 > 0 → weight = 8334995
- Backend 1: effective = 20690000 - 4025000 = 16665000, miss_rate=0.1945 > 0 → weight = 16665000
- Backend 2: effective = 19145000 - 0 = 19145000, miss_rate=0.0 → weight = 19145000 * 1.1 = 21059500

All weights must be ≥ 1, and we need positive total weight.

```cpp
#include <cstdint>

struct StrategyInput {
    uint32_t packet_hash;
    uint32_t packet_index;
};

struct ServerState {
    uint32_t address;
    uint64_t mac;
    uint32_t active_connections;
    uint32_t weight;
};

class Strategy {
public:
    virtual ServerState *select(const StrategyInput &s) = 0;
    virtual ~Strategy() = default;
};

class WaterFillingStrategy : public Strategy {
private:
    ServerState *servers;
    int server_count;
    
    // Water-filling weights based on latest snapshot:
    // Backend 0: effective = 8334995, miss_rate=0.18 > 0 -> weight = 8334995
    // Backend 1: effective = 16665000, miss_rate=0.1945 > 0 -> weight = 16665000
    // Backend 2: effective = 19145000, miss_rate=0.0 -> weight = 19145000 * 1.1 = 21059500
    constexpr static uint32_t kWeights[3] = {
        8334995,
        16665000,
        21059500
    };
    
    uint32_t cumulative_weights[3];
    uint32_t total_weight;

public:
    WaterFillingStrategy(ServerState *servers, int count)
        : servers(servers), server_count(count), total_weight(0) {
        // Precompute cumulative weights
        for (int i = 0; i < server_count; ++i) {
            total_weight += kWeights[i];
            cumulative_weights[i] = total_weight;
        }
    }

    ServerState *select(const StrategyInput &s) override {
        uint32_t target = s.packet_hash % total_weight;
        
        // Binary search or linear walk for cumulative weight
        for (int i = 0; i < server_count; ++i) {
            if (target < cumulative_weights[i]) {
                return &servers[i];
            }
        }
        
        // Fallback to last server
        return &servers[server_count - 1];
    }

    ~WaterFillingStrategy() override = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new WaterFillingStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```