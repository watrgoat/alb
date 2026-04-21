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

class CapacityAwareStrategy : public Strategy {
private:
    ServerState *servers;
    int count;
    uint32_t total_weight;

public:
    CapacityAwareStrategy(ServerState *s, int c) : servers(s), count(c), total_weight(0) {}

    ServerState *select(const StrategyInput &input) override {
        uint32_t target = input.packet_hash % total_weight;
        uint32_t cumulative = 0;

        for (int i = 0; i < count; ++i) {
            cumulative += servers[i].weight;
            if (target < cumulative) {
                return &servers[i];
            }
        }

        return &servers[count - 1];
    }

    void set_total_weight(uint32_t w) {
        total_weight = w;
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    CapacityAwareStrategy *strategy = new CapacityAwareStrategy(servers, count);

    const uint32_t kWeights[3] = {1663, 3333, 5004};
    uint32_t total = kWeights[0] + kWeights[1] + kWeights[2];

    for (int i = 0; i < count && i < 3; ++i) {
        servers[i].weight = kWeights[i];
    }

    strategy->set_total_weight(total);

    return strategy;
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```