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
    int server_count;
    static constexpr uint32_t kWeights[3] = {3333, 3333, 3334};

public:
    CapacityAwareStrategy(ServerState *srv, int cnt)
        : servers(srv), server_count(cnt) {}

    ServerState *select(const StrategyInput &input) override {
        uint32_t total_weight = kWeights[0] + kWeights[1] + kWeights[2];
        uint32_t target = input.packet_hash % total_weight;
        
        uint32_t cumulative = 0;
        for (int i = 0; i < server_count; ++i) {
            cumulative += kWeights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }
        
        return &servers[server_count - 1];
    }
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```