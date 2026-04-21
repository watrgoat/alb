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

class Strategy
{
      public:
	virtual ServerState *select(const StrategyInput &s) = 0;
	virtual ~Strategy() = default;
};

constexpr uint32_t kWeights[3] = {5000, 1667, 3333};

class CapacityAwareStrategy : public Strategy {
private:
	ServerState *servers;
	int server_count;
	uint32_t cumulative_weights[3];

public:
	CapacityAwareStrategy(ServerState *s, int count) 
		: servers(s), server_count(count) {
		uint32_t sum = 0;
		for (int i = 0; i < 3; ++i) {
			sum += kWeights[i];
			cumulative_weights[i] = sum;
		}
	}

	ServerState *select(const StrategyInput &input) override {
		uint32_t target = input.packet_hash % cumulative_weights[2];
		
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
	return new CapacityAwareStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s) {
	delete s;
}
```