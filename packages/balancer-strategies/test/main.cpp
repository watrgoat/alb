#include "strategy.hpp"
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>

int main()
{
	// set up some fake servers
	ServerState servers[3] = {
	    {.address = 0xC0A80001,
	     .mac = 0,
	     .active_connections = 0,
	     .weight = 1}, // 192.168.0.1
	    {.address = 0xC0A80002,
	     .mac = 0,
	     .active_connections = 0,
	     .weight = 1}, // 192.168.0.2
	    {.address = 0xC0A80003,
	     .mac = 0,
	     .active_connections = 0,
	     .weight = 1}, // 192.168.0.3
	};

	// load the strategy
	const char *lib_path = getenv("STRATEGY_LIB");
	if (!lib_path)
		lib_path = "./build/libteststrategy.so";
	void *handle = dlopen(lib_path, RTLD_NOW);
	if (!handle) {
		printf("dlopen failed: %s\n", dlerror());
		return 1;
	}

	auto create = (Strategy * (*)(ServerState *, int))
	    dlsym(handle, "create_strategy");
	auto destroy = (void (*)(Strategy *))dlsym(handle, "destroy_strategy");

	if (!create || !destroy) {
		printf("dlsym failed: %s\n", dlerror());
		dlclose(handle);
		return 1;
	}

	Strategy *balancer = create(servers, 3);

	for (int i = 0; i < 10; i++) {
		StrategyInput input = {.packet_hash = (uint32_t)i,
				       .packet_index = (uint32_t)i};

		ServerState *target = balancer->select(input);
		printf("packet %d -> server %x\n", i, target->address);
	}

	destroy(balancer);
	dlclose(handle);
	return 0;
}
