#pragma once
#include <cstdint>

/*
 StrategyInput is an abstract class that handles the inputs. It should include
all possible needed parameters for every implementation.
- packet_hash
- packet_index
*/
struct StrategyInput {
	uint32_t packet_hash;
	uint32_t packet_index;
};

/*
ServerState can have
- address
- active connections
- weight
*/
struct ServerState {
	uint32_t address; // ipv4
	uint64_t mac;	  // mac

	uint32_t active_connections;
	uint32_t weight;
};

class Strategy
{
      public:
	virtual ServerState *select(const StrategyInput &s) = 0;
	// virtual void update() = 0; // TODO: Implement program->lib update
	// communication
	virtual ~Strategy() = default;
};

extern "C" Strategy *create_strategy(ServerState *servers, int count);
extern "C" void destroy_strategy(Strategy *s);
