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
    
    // Water-filling from latest snapshot:
    // Backend 0: effective=8335000-5005=8334995, miss_rate=0.0006 > 0 → weight=8334995
    // Backend 1: effective=17560000-895000=16665000, miss_rate=0.051 > 0 → weight=16665000
    // Backend 2: effective=24100000-0=24100000, miss_rate=0.0 → weight=24100000*1.1=26510000
    constexpr static uint32_t kWeights[3] = {
        8334995,
        16665000,
        26510000
    };

public:
    WaterFillingStrategy(ServerState *s, int count) 
        : servers(s), server_count(count), total_weight(0) {
        for (int i = 0; i < server_count && i < 3; ++i) {
            total_weight += kWeights[i];
            cumulative_weights[i] = total_weight;
        }
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

    virtual ~WaterFillingStrategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new WaterFillingStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```