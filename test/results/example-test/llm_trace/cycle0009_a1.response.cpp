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
    
    // Water-filling algorithm from latest snapshot:
    // Backend 0: packets_sent=8575000, packets_missed=240005, miss_rate=0.028
    //   effective = 8575000 - 240005 = 8334995
    //   saturated (miss_rate > 0) -> weight = 8334995
    // Backend 1: packets_sent=15790000, packets_missed=0, miss_rate=0.0
    //   effective = 15790000 - 0 = 15790000
    //   healthy (miss_rate == 0) -> weight = 15790000 * 1.1 = 17369000
    // Backend 2: packets_sent=25635000, packets_missed=635000, miss_rate=0.0248
    //   effective = 25635000 - 635000 = 25000000
    //   saturated (miss_rate > 0) -> weight = 25000000
    static constexpr uint32_t kWeights[3] = {8334995, 17369000, 25000000};
    
public:
    WaterFillingStrategy(ServerState *s, int count)
        : servers(s), server_count(count), total_weight(0) {
        total_weight = kWeights[0] + kWeights[1] + kWeights[2];
        cumulative_weights[0] = kWeights[0];
        cumulative_weights[1] = kWeights[0] + kWeights[1];
        cumulative_weights[2] = total_weight;
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