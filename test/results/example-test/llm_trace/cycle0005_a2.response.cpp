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
    
    constexpr static uint32_t kWeights[3] = {
        8334995,
        16665000,
        21059500
    };
    
    uint32_t cumulative_weights[3];
    uint32_t total_weight;
    
    void compute_cumulative() {
        cumulative_weights[0] = kWeights[0];
        cumulative_weights[1] = cumulative_weights[0] + kWeights[1];
        cumulative_weights[2] = cumulative_weights[1] + kWeights[2];
        total_weight = cumulative_weights[2];
    }

public:
    WaterFillingStrategy(ServerState *servers_ptr, int count) 
        : servers(servers_ptr), server_count(count) {
        compute_cumulative();
    }

    ServerState *select(const StrategyInput &s) override {
        if (server_count <= 0 || total_weight == 0) {
            return &servers[0];
        }
        
        uint32_t target = s.packet_hash % total_weight;
        
        for (int i = 0; i < server_count; i++) {
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