```cpp
#include <cstdint>

struct Strategy {
    ServerState *servers;
    int count;
    uint32_t total_weight;
    uint32_t cumulative_weights[3];
    
    Strategy(ServerState *s, int c) : servers(s), count(c) {
        constexpr uint32_t kWeights[3] = {1667, 3333, 5000};
        
        total_weight = 0;
        for (int i = 0; i < count; ++i) {
            total_weight += kWeights[i];
            cumulative_weights[i] = total_weight;
        }
    }
    
    virtual ServerState *select(const StrategyInput &input) {
        uint32_t target = input.packet_hash % total_weight;
        
        for (int i = 0; i < count; ++i) {
            if (target < cumulative_weights[i]) {
                return &servers[i];
            }
        }
        
        return &servers[count - 1];
    }
    
    virtual ~Strategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new Strategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```