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

	constexpr int N = 3;
	ServerState servers[N] = {
	    {0xC0A80001u, 0, 0, 1},
	    {0xC0A80002u, 0, 0, 2},
	    {0xC0A80003u, 0, 0, 3},
	};

	Strategy *s = cr(servers, N);
	if (!s) {
		fprintf(stderr, "create_strategy returned null\n");
		dlclose(h);
		return 5;
	}

	for (uint32_t i = 0; i < 100; i++) {
		StrategyInput in{i * 0x9E3779B1u, i};
		ServerState *r = s->select(in);
		if (!r || r < servers || r >= servers + N) {
			fprintf(stderr,
				"select returned out-of-range pointer\n");
			de(s);
			dlclose(h);
			return 6;
		}
	}

	de(s);
	dlclose(h);
	return 0;
}
