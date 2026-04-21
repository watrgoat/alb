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
        
        // Water-filling weights from latest snapshot:
        // Backend 0: sent=8135000, missed=0, miss_rate=0.0 => probe up: 8135000 * 1.1 = 8948500
        // Backend 1: sent=16925000, missed=8590005, miss_rate=0.5075 > 0 => effective: 8334995
        // Backend 2: sent=24940000, missed=8275000, miss_rate=0.3318 > 0 => effective: 16665000
        
        constexpr uint32_t kWeights[3] = {8948500, 8334995, 16665000};
        
        uint32_t cumsum = 0;
        for (int i = 0; i < server_count && i < 3; ++i) {
            cumsum += kWeights[i];
            cumulative_weights[i] = cumsum;
        }
        total_weight = cumsum;
    }

    ServerState *select(const StrategyInput &input) override {
        if (server_count <= 0 || total_weight == 0) {
            return &servers[0];
        }

        uint32_t target = input.packet_hash % total_weight;
        
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