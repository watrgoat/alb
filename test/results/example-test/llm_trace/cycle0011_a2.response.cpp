```cpp
#include <cstdint>

#pragma once
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

class Strategy
{
      public:
	virtual ServerState *select(const StrategyInput &s) = 0;
	virtual ~Strategy() = default;
};

class CapacityAwareStrategy : public Strategy {
    private:
        ServerState *servers;
        int server_count;
        uint32_t cumulative_weights[3];
        uint32_t total_weight;

        void compute_cumulative() {
            cumulative_weights[0] = kWeights[0];
            for (int i = 1; i < server_count; i++) {
                cumulative_weights[i] = cumulative_weights[i-1] + kWeights[i];
            }
            total_weight = cumulative_weights[server_count - 1];
        }

    public:
        static constexpr uint32_t kWeights[3] = {3333, 3333, 3333};

        CapacityAwareStrategy(ServerState *servers_, int count)
            : servers(servers_), server_count(count), total_weight(0) {
            compute_cumulative();
        }

        ServerState *select(const StrategyInput &input) override {
            if (server_count == 0) return nullptr;
            
            uint32_t target = input.packet_hash % total_weight;
            
            for (int i = 0; i < server_count; i++) {
                if (target < cumulative_weights[i]) {
                    return &servers[i];
                }
            }
            
            return &servers[server_count - 1];
        }

        ~CapacityAwareStrategy() = default;
};

constexpr uint32_t CapacityAwareStrategy::kWeights[3];

extern "C" Strategy *create_strategy(ServerState *servers, int count) {
    return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
    delete s;
}
```