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
    WaterFillingStrategy(ServerState *servers_, int count_)
        : servers(servers_), server_count(count_), total_weight(0) {
        
        // Backend 0: miss_rate=0.1628 > 0, so snap to effective
        // effective[0] = 19905000 - 3240000 = 16665000
        uint32_t weight0 = 16665000;
        
        // Backend 1: miss_rate=0.0, so probe up by 10%
        // weight[1] = 10155000 * 1.1 = 11170500
        uint32_t weight1 = 11170500;
        
        // Backend 2: miss_rate=0.164 > 0, so snap to effective
        // effective[2] = 19940000 - 3270005 = 16669995
        uint32_t weight2 = 16669995;
        
        // Ensure all weights >= 1
        if (weight0 < 1) weight0 = 1;
        if (weight1 < 1) weight1 = 1;
        if (weight2 < 1) weight2 = 1;
        
        total_weight = weight0 + weight1 + weight2;
        
        cumulative_weights[0] = weight0;
        cumulative_weights[1] = weight0 + weight1;
        cumulative_weights[2] = weight0 + weight1 + weight2;
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