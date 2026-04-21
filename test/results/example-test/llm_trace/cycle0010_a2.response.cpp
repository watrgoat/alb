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
    static constexpr uint32_t kWeights[3] = {4960, 1654, 3386};
    
    uint32_t compute_total_weight() const {
        uint32_t total = 0;
        for (int i = 0; i < server_count; i++) {
            total += kWeights[i];
        }
        return total;
    }

public:
    CapacityAwareStrategy(ServerState *servers_arg, int count)
        : servers(servers_arg), server_count(count) {}

    ServerState *select(const StrategyInput &input) override {
        uint32_t total_weight = compute_total_weight();
        if (total_weight == 0) {
            return servers;
        }

        uint32_t target = input.packet_hash % total_weight;
        uint32_t cumulative = 0;

        for (int i = 0; i < server_count; i++) {
            cumulative += kWeights[i];
            if (target < cumulative) {
                return &servers[i];
            }
        }

        return &servers[server_count - 1];
    }

    ~CapacityAwareStrategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```