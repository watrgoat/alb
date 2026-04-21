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
    uint32_t cumulative_weights[3];
    uint32_t total_weight;
    
    static constexpr uint32_t kWeights[3] = {16665000, 3665000, 16665000};

public:
    WaterFillingStrategy(ServerState *servers_ptr, int count)
        : servers(servers_ptr), server_count(count), total_weight(0) {
        
        total_weight = 0;
        for (int i = 0; i < server_count; ++i) {
            total_weight += kWeights[i];
        }
        
        cumulative_weights[0] = kWeights[0];
        for (int i = 1; i < server_count; ++i) {
            cumulative_weights[i] = cumulative_weights[i-1] + kWeights[i];
        }
    }
    
    ServerState *select(const StrategyInput &s) override {
        uint32_t target = s.packet_hash % total_weight;
        
        for (int i = 0; i < server_count; ++i) {
            if (target < cumulative_weights[i]) {
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