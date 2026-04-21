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

class LoadBalancerStrategy : public Strategy
{
      private:
	ServerState *servers;
	int server_count;
	static constexpr uint32_t kWeights[3] = {3003, 1000, 2000};
	uint32_t total_weight;

	uint32_t cumulative_weights[3];

      public:
	LoadBalancerStrategy(ServerState *servers_, int count)
	    : servers(servers_), server_count(count)
	{
		total_weight = 0;
		for (int i = 0; i < server_count && i < 3; ++i) {
			total_weight += kWeights[i];
		}

		uint32_t cumsum = 0;
		for (int i = 0; i < server_count && i < 3; ++i) {
			cumsum += kWeights[i];
			cumulative_weights[i] = cumsum;
		}
	}

	ServerState *select(const StrategyInput &s) override
	{
		uint32_t target = s.packet_hash % total_weight;

		for (int i = 0; i < server_count && i < 3; ++i) {
			if (target < cumulative_weights[i]) {
				return &servers[i];
			}
		}

		return &servers[0];
	}
};

extern "C" Strategy *create_strategy(ServerState *servers, int count)
{
	return new LoadBalancerStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s)
{
	delete s;
}
```