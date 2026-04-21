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
    
public:
    WaterFillingStrategy(ServerState *s, int count) 
        : servers(s), server_count(count), total_weight(0) {
        
        // Water-filling algorithm from snapshot:
        // Backend 0: sent=8360000, missed=25005, effective=8334995, miss_rate=0.003 > 0
        //   -> weight = 8334995
        // Backend 1: sent=16480000, missed=0, effective=16480000, miss_rate=0.0
        //   -> weight = 16480000 * 1.1 = 18128000
        // Backend 2: sent=25160000, missed=160000, effective=25000000, miss_rate=0.0064 > 0
        //   -> weight = 25000000
        
        constexpr uint32_t kWeights[3] = {8334995, 18128000, 25000000};
        
        cumulative_weights[0] = kWeights[0];
        cumulative_weights[1] = cumulative_weights[0] + kWeights[1];
        cumulative_weights[2] = cumulative_weights[1] + kWeights[2];
        total_weight = cumulative_weights[2];
    }
    
    ServerState *select(const StrategyInput &input) override {
        uint32_t target = input.packet_hash % total_weight;
        
        if (target < cumulative_weights[0]) {
            return &servers[0];
        } else if (target < cumulative_weights[1]) {
            return &servers[1];
        } else {
            return &servers[2];
        }
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new WaterFillingStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```