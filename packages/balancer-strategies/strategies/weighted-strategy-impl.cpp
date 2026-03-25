#include "strategy.hpp"

class WeightedStrategy : public Strategy
{
	ServerState *servers;
	int count;
	uint32_t total_weight;

      public:
	WeightedStrategy(ServerState *s, int n)
	    : servers(s), count(n), total_weight(0)
	{
		for (int i = 0; i < n; i++)
			total_weight += s[i].weight;
	}

	ServerState *select(const StrategyInput &in) override
	{
		uint32_t target = in.packet_hash % total_weight;
		uint32_t cumulative = 0;
		for (int i = 0; i < count; i++) {
			cumulative += servers[i].weight;
			if (target < cumulative)
				return &servers[i];
		}
		return &servers[count - 1];
	}
};

extern "C" Strategy *create_strategy(ServerState *servers, int count)
{
	return new WeightedStrategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s)
{
	delete s;
}
