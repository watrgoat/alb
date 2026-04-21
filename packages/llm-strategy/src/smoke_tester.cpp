// exit 0 on success, nonzero on failure. called by the Python generator in a
// subprocess so a crashing candidate .so doesn't take down the generator.
#include "strategy.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <path-to-.so>\n", argv[0]);
		return 2;
	}
	const char *path = argv[1];

	void *h = dlopen(path, RTLD_NOW);
	if (!h) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 3;
	}

	auto cr =
	    (Strategy * (*)(ServerState *, int)) dlsym(h, "create_strategy");
	auto de = (void (*)(Strategy *))dlsym(h, "destroy_strategy");
	if (!cr || !de) {
		fprintf(stderr, "dlsym: %s\n", dlerror());
		dlclose(h);
		return 4;
	}

	// all weights=1 mirrors the ALB's default config (config-4port.yaml
	// and similar): strategies that use servers[i].weight will produce
	// the same distribution here as they do in the running ALB. stub-
	// and LLM-generated strategies that bake in their own weight
	// constants will use those constants regardless.
	constexpr int N = 3;
	ServerState servers[N] = {
	    {0xC0A80001u, 0, 0, 1},
	    {0xC0A80002u, 0, 0, 1},
	    {0xC0A80003u, 0, 0, 1},
	};

	Strategy *s = cr(servers, N);
	if (!s) {
		fprintf(stderr, "create_strategy returned null\n");
		dlclose(h);
		return 5;
	}

	// two-phase: first a quick correctness smoke (any out-of-range
	// pointer fails the test), then a distribution probe over 10k
	// well-distributed hash inputs. the second phase gives the
	// generator caller an empirical ratio to stash in
	// current_weights.json — lets the simulate-mode adapter treat
	// LLM-generated .so's the same as stub-generated ones.
	constexpr int kSmokeCalls = 100;
	constexpr int kProbeCalls = 10000;
	int counts[N] = {0};

	for (uint32_t i = 0; i < kSmokeCalls + kProbeCalls; i++) {
		// splitmix32-style avalanche so sequential indices produce
		// well-distributed hashes — matters for weighted strategies
		// using `hash % total_weight`.
		uint32_t x = i + 1;
		x = (x ^ (x >> 16)) * 0x7FEB352Du;
		x = (x ^ (x >> 15)) * 0x846CA68Bu;
		x = x ^ (x >> 16);
		StrategyInput in{x, i};
		ServerState *r = s->select(in);
		if (!r || r < servers || r >= servers + N) {
			fprintf(stderr,
				"select returned out-of-range pointer\n");
			de(s);
			dlclose(h);
			return 6;
		}
		if (i >= kSmokeCalls) {
			counts[r - servers]++;
		}
	}

	// machine-readable distribution on the last stdout line — the
	// Python caller parses this to recover the strategy's effective
	// weight ratio without having to read the .so's source.
	printf("{\"distribution\":[");
	for (int i = 0; i < N; i++)
		printf("%s%d", i ? "," : "", counts[i]);
	printf("],\"samples\":%d}\n", kProbeCalls);

	de(s);
	dlclose(h);
	return 0;
}
