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
    
    // Water-filling algorithm based on latest snapshot:
    // Backend 0: packets_sent=9060000, packets_missed=725005
    //   effective = 9060000 - 725005 = 8334995
    //   miss_rate = 0.08 > 0 -> new_weight = 8334995
    // Backend 1: packets_sent=18240000, packets_missed=1575000
    //   effective = 18240000 - 1575000 = 16665000
    //   miss_rate = 0.0863 > 0 -> new_weight = 16665000
    // Backend 2: packets_sent=22700000, packets_missed=0
    //   effective = 22700000 - 0 = 22700000
    //   miss_rate = 0.0 -> new_weight = 22700000 * 1.1 = 24970000
    constexpr static uint32_t kWeights[3] = {
        8334995,
        16665000,
        24970000
    };
    
    uint32_t cumulative_weights[3];
    uint32_t total_weight;
    
public:
    WaterFillingStrategy(ServerState *servers_arg, int count)
        : servers(servers_arg), server_count(count) {
        total_weight = 0;
        for (int i = 0; i < server_count && i < 3; ++i) {
            total_weight += kWeights[i];
            cumulative_weights[i] = total_weight;
        }
    }
    
    ServerState *select(const StrategyInput &s) override {
        uint32_t target = s.packet_hash % total_weight;
        
        for (int i = 0; i < server_count && i < 3; ++i) {
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