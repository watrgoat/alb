```cpp
#include <cstdint>

struct Strategy
{
	ServerState *servers;
	int count;
	constexpr static uint32_t kWeights[3] = {1000, 3333, 1000};

	Strategy(ServerState *s, int c) : servers(s), count(c) {}

	virtual ServerState *select(const StrategyInput &input)
	{
		uint32_t total_weight = 0;
		for (int i = 0; i < count; ++i) {
			total_weight += kWeights[i];
		}

		uint32_t target = input.packet_hash % total_weight;
		uint32_t cumulative = 0;

		for (int i = 0; i < count; ++i) {
			cumulative += kWeights[i];
			if (target < cumulative) {
				return &servers[i];
			}
		}

		return &servers[0];
	}

	virtual ~Strategy() = default;
};

class StrategyImpl : public Strategy
{
      public:
	StrategyImpl(ServerState *s, int c) : Strategy(s, c) {}

	virtual ServerState *select(const StrategyInput &input) override
	{
		uint32_t total_weight = 0;
		for (int i = 0; i < count; ++i) {
			total_weight += kWeights[i];
		}

		uint32_t target = input.packet_hash % total_weight;
		uint32_t cumulative = 0;

		for (int i = 0; i < count; ++i) {
			cumulative += kWeights[i];
			if (target < cumulative) {
				return &servers[i];
			}
		}

		return &servers[0];
	}
};

extern "C" Strategy *create_strategy(ServerState *servers, int count)
{
	return new StrategyImpl(servers, count);
}

extern "C" void destroy_strategy(Strategy *s)
{
	delete s;
}
```

Wait, let me recalculate based on the algorithm provided:

```cpp
#include <cstdint>

class StrategyImpl : public Strategy
{
      private:
	ServerState *servers;
	int count;
	static constexpr uint32_t kWeights[3] = {1000, 3333, 1000};

      public:
	StrategyImpl(ServerState *s, int c) : servers(s), count(c) {}

	virtual ServerState *select(const StrategyInput &input) override
	{
		uint32_t total_weight = 0;
		for (int i = 0; i < count; ++i) {
			total_weight += kWeights[i];
		}

		uint32_t target = input.packet_hash % total_weight;
		uint32_t cumulative = 0;

		for (int i = 0; i < count; ++i) {
			cumulative += kWeights[i];
			if (target < cumulative) {
				return &servers[i];
			}
		}

		return &servers[0];
	}

	virtual ~StrategyImpl() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count)
{
	return new StrategyImpl(servers, count);
}

extern "C" void destroy_strategy(Strategy *s)
{
	delete s;
}
```