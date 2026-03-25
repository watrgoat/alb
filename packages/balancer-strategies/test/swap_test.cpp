#include "strategy.hpp"
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>

static int hits[3];

static void run_packets(Strategy *s, ServerState *servers, int nservers,
			int npkts)
{
	for (int i = 0; i < nservers; i++)
		hits[i] = 0;

	for (int i = 0; i < npkts; i++) {
		StrategyInput input = {.packet_hash = (uint32_t)i,
				       .packet_index = (uint32_t)i};
		ServerState *target = s->select(input);
		int idx = (int)(target - servers);
		hits[idx]++;
	}

	for (int i = 0; i < nservers; i++)
		printf("  server %d (w=%u): %d/%d packets\n", i,
		       servers[i].weight, hits[i], npkts);
}

static void *load_lib(const char *path,
		      Strategy *(*&create)(ServerState *, int),
		      void (*&destroy)(Strategy *))
{
	void *h = dlopen(path, RTLD_NOW);
	if (!h) {
		printf("dlopen failed: %s\n", dlerror());
		return nullptr;
	}
	create =
	    (Strategy * (*)(ServerState *, int)) dlsym(h, "create_strategy");
	destroy = (void (*)(Strategy *))dlsym(h, "destroy_strategy");
	if (!create || !destroy) {
		printf("dlsym failed: %s\n", dlerror());
		dlclose(h);
		return nullptr;
	}
	return h;
}

int main()
{
	const char *rr_path = getenv("RR_LIB");
	const char *wt_path = getenv("WEIGHTED_LIB");
	if (!rr_path || !wt_path) {
		printf("RR_LIB and WEIGHTED_LIB must be set\n");
		return 1;
	}

	ServerState servers[3] = {
	    {.address = 0xC0A80001,
	     .mac = 0,
	     .active_connections = 0,
	     .weight = 1},
	    {.address = 0xC0A80002,
	     .mac = 0,
	     .active_connections = 0,
	     .weight = 2},
	    {.address = 0xC0A80003,
	     .mac = 0,
	     .active_connections = 0,
	     .weight = 3},
	};

	Strategy *(*create)(ServerState *, int) = nullptr;
	void (*destroy)(Strategy *) = nullptr;
	void *handle;

	printf("=== round-robin (weights ignored) ===\n");
	handle = load_lib(rr_path, create, destroy);
	if (!handle)
		return 1;
	Strategy *rr = create(servers, 3);
	run_packets(rr, servers, 3, 12);
	destroy(rr);
	dlclose(handle);

	printf("=== weighted (w=1:2:3, expect ~2:4:6) ===\n");
	handle = load_lib(wt_path, create, destroy);
	if (!handle)
		return 1;
	Strategy *wt = create(servers, 3);
	run_packets(wt, servers, 3, 12);
	destroy(wt);
	dlclose(handle);

	return 0;
}
