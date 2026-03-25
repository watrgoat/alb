#pragma once

#include <atomic>
#include <cstdint>

#include "strategy.hpp"

#define BURST_SIZE 32

struct StrategySlot {
	void *dl_handle;
	Strategy *(*create)(ServerState *, int);
	void (*destroy)(Strategy *);
	std::atomic<int32_t> in_flight{0};
};

extern StrategySlot slots[2];
extern std::atomic<int> active_index;
extern std::atomic<bool> running;
extern ServerState server_states[];
extern int num_servers;

bool load_into_slot(StrategySlot *slot, const char *path);
void load_fallback_slot(StrategySlot *slot);
int worker_main(void *arg);
int manager_main(void *arg);
