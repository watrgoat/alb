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

// Computed weights based on capacity hints and observed metrics
constexpr uint32_t kWeights[3] = {1667, 3333, 5000};
constexpr uint32_t kTotalWeight = 1667 + 3333 + 5000;

class CapacityAwareStrategy : public Strategy {
private:
    ServerState *servers;
    int count;

public:
    CapacityAwareStrategy(ServerState *servers_, int count_)
        : servers(servers_), count(count_) {}

    ServerState *select(const StrategyInput &input) override {
        if (count <= 0) {
            return nullptr;
        }

        uint32_t hash = input.packet_hash;
        uint32_t target = hash % kTotalWeight;
        
        uint32_t cumulative = 0;
        for (int i = 0; i < count; ++i) {
            cumulative += kWeights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }
        
        return &servers[count - 1];
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```