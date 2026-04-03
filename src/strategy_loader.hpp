#pragma once

#include <atomic>
#include <cstdint>

#include "strategy.hpp"
#include "table.hpp"

#define BURST_SIZE 32

struct StrategySlotData {
	Strategy *(*create)(ServerState *, int);
	void (*destroy)(Strategy *);
};

using StrategySlot = Slot<StrategySlotData>;

extern HotSwapTable<StrategySlotData> strategy_table;
extern std::atomic<bool> running;
extern ServerState server_states[];
extern int num_servers;

bool load_into_slot(StrategySlot *slot, const char *path);
void load_fallback_slot(StrategySlot *slot);
int worker_main(void *arg);
int manager_main(void *arg);
