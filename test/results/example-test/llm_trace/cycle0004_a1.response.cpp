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
    // Backend 0: effective = 17860000 - 9525005 = 8334995, miss_rate=0.5333 > 0 -> weight = 8334995
    // Backend 1: effective = 17580000 - 915000 = 16665000, miss_rate=0.052 > 0 -> weight = 16665000
    // Backend 2: effective = 14560000 - 0 = 14560000, miss_rate=0.0 == 0 -> weight = 14560000 * 1.1 = 16016000
    constexpr static uint32_t kWeights[3] = {
        8334995,
        16665000,
        16016000
    };
    
    uint32_t cumulative_weights[3];
    uint32_t total_weight;

public:
    WaterFillingStrategy(ServerState *servers_, int count_)
        : servers(servers_), server_count(count_), total_weight(0) {
        cumulative_weights[0] = 0;
        cumulative_weights[1] = 0;
        cumulative_weights[2] = 0;
        
        for (int i = 0; i < server_count && i < 3; ++i) {
            total_weight += kWeights[i];
            if (i > 0) {
                cumulative_weights[i] = cumulative_weights[i-1] + kWeights[i-1];
            }
        }
    }

    ServerState *select(const StrategyInput &s) override {
        if (server_count <= 0 || total_weight == 0) {
            return &servers[0];
        }
        
        uint32_t target = s.packet_hash % total_weight;
        
        for (int i = 0; i < server_count && i < 3; ++i) {
            uint32_t cumul = cumulative_weights[i];
            uint32_t next_cumul = cumul + kWeights[i];
            
            if (target < next_cumul) {
                return &servers[i];
            }
        }
        
        return &servers[server_count - 1];
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new WaterFillingStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```