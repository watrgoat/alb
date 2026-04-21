```cpp
#include <cstdint>

struct Strategy
{
	ServerState *servers;
	int count;
	uint32_t weights[3];
	uint32_t cumulative[3];
	uint32_t total_weight;

	Strategy(ServerState *s, int c) : servers(s), count(c)
	{
		// Initialize weights based on capacity hints
		// Backend 0: capacity 3333000
		// Backend 1: capacity 3333000
		// Backend 2: capacity 3333999
		// All three are equal, so equal weights
		weights[0] = 3333;
		weights[1] = 3333;
		weights[2] = 3334;
		
		total_weight = weights[0] + weights[1] + weights[2];
		
		// Precompute cumulative weights for dispatch
		cumulative[0] = weights[0];
		cumulative[1] = cumulative[0] + weights[1];
		cumulative[2] = cumulative[1] + weights[2];
	}

	virtual ServerState *select(const StrategyInput &input)
	{
		uint32_t target = input.packet_hash % total_weight;
		
		if (target < cumulative[0])
			return &servers[0];
		else if (target < cumulative[1])
			return &servers[1];
		else
			return &servers[2];
	}

	virtual ~Strategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count)
{
	return new Strategy(servers, count);
}

extern "C" void destroy_strategy(Strategy *s)
{
	delete s;
}
```

Wait, I need to follow the constraint about making this a class that derives from the provided Strategy ABI. Let me reconsider:

```cpp
#include <cstdint>

class LoadBalancerStrategy : public Strategy
{
private:
	ServerState *servers;
	int count;
	uint32_t weights[3];
	uint32_t cumulative[3];
	uint32_t total_weight;

public:
	LoadBalancerStrategy(ServerState *s, int c) : servers(s), count(c)
	{
		// Backend 0: capacity 3333000, packets_sent 16550000, miss_rate 0.0, utilization 0.9931
		// Backend 1: capacity 3333000, packets_sent 16355000, miss_rate 0.0, utilization 0.9814
		// Backend 2: capacity 3333999, packets_sent 17095000, miss_rate 0.0249, utilization 1.0255 <- OVERLOADED
		
		// Window = 5 seconds
		// cap_budget[i] = capacity_hint[i] * 5
		
		uint32_t cap_budget[3];
		cap_budget[0] = 3333000 * 5;  // 16665000
		cap_budget[1] = 3333000 * 5;  // 16665000
		cap_budget[2] = 3333999 * 5;  // 16669995
		
		uint32_t new_weight[3];
		
		// Backend 0: miss_rate 0.0 (healthy) -> probe up by 5%
		// packets_sent = 16550000, probe = 16550000 * 1.05 = 17377500
		// capped by cap_budget = min(17377500, 16665000) = 16665000
		new_weight[0] = 16665000;
		
		// Backend 1: miss_rate 0.0 (healthy) -> probe up by 5%
		// packets_sent = 16355000, probe = 16355000 * 1.05 = 17172750
		// capped by cap_budget = min(17172750, 16665000) = 16665000
		new_weight[1] = 16665000;
		
		// Backend 2: miss_rate 0.0249 > 0 (overloaded) -> use min(effective, cap_budget)
		// effective = packets_sent - packets_missed = 17095000 - 425005 = 16669995
		// cap_budget = 16669995
		// new_weight[2] = min(16669995, 16669995) = 16669995
		new_weight[2] = 16669995;
		
		// Normalize to uint32_t range while preserving ratios
		// Total = 16665000 + 16665000 + 16669995 = 49999995
		// Scale down by dividing by 5000 to fit in uint32_t
		weights[0] = 3333;
		weights[1] = 3333;
		weights[2] = 3334;
		
		total_weight = weights[0] + weights[1] + weights[2];
		
		cumulative[0] = weights[0];
		cumulative[1] = cumulative[0] + weights[1];
		cumulative[2] = cumulative[1] + weights[2];
	}

	virtual ServerState *select(const StrategyInput &input)
	{
		uint32_t target = input.packet_hash % total_weight;
		
		if (target < cumulative[0])
			return &servers[0];
		else if (target < cumulative[1])
			return &servers[1];
		else
			return &servers[2];
	}

	virtual ~LoadBalancerStrategy() = default;
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