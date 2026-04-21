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
        16665000,
        13832000,
        10668995
    };

    uint32_t cumulative_weights[3];
    uint32_t total_weight;

public:
    WaterFillingStrategy(ServerState *servers_, int count_)
        : servers(servers_), server_count(count_), total_weight(0) {
        
        total_weight = 0;
        for (int i = 0; i < server_count && i < 3; ++i) {
            total_weight += kWeights[i];
            cumulative_weights[i] = total_weight;
        }
    }

    ServerState *select(const StrategyInput &input) override {
        if (server_count == 0 || total_weight == 0) {
            return nullptr;
        }
        
        uint32_t target = input.packet_hash % total_weight;
        
        for (int i = 0; i < server_count && i < 3; ++i) {
            if (target < cumulative_weights[i]) {
                return &servers[i];
            }
        }
        
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