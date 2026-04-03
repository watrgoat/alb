#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

// single process hot-swap slot with reference counting
// uses in_flight to track active users before unloading
template <typename T> struct Slot {
	T *data = nullptr;
	void *dl_handle = nullptr;
	std::atomic<int32_t> in_flight{0};

	void acquire()
	{
		in_flight.fetch_add(1, std::memory_order_acq_rel);
	} // bump refcount
	void release()
	{
		in_flight.fetch_sub(1, std::memory_order_release);
	} // drop refcount
	bool idle() const
	{
		return in_flight.load(std::memory_order_acquire) ==
		       0; // check if drainable
	}
};

// two slot table for hot swapping: one active, one for loading new version
// use: load into inactive slot, swap active_index, wait for old to drain
template <typename T, size_t N = 2> struct HotSwapTable {
	Slot<T> slots[N];
	std::atomic<size_t> active_index{0};

	Slot<T> &active()
	{
		return slots[active_index.load(std::memory_order_acquire)];
	}
	Slot<T> &inactive()
	{
		return slots[active_index.load(std::memory_order_acquire) ^ 1];
	}

	void swap()
	{
		size_t old = active_index.load(std::memory_order_acquire);
		active_index.store(old ^ 1, std::memory_order_release);
	}
};

// cross-process shared memory slot (for future)
// stores path instead of pointers since pointers aren't shareable across
// processes
struct SharedSlot {
	std::atomic<uint64_t> version;
	std::atomic<int32_t> refcount;
	std::atomic<bool> active;
	char dll_path[256];
};

struct SharedVersionTable {
	std::atomic<uint32_t> latest_index;
	SharedSlot slots[8];
};
