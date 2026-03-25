#include <atomic>

#pragma once

struct SharedSlot {
	std::atomic<uint64_t> version; // monotonic version counter
	std::atomic<int32_t> refcount; // how many processes are mid-call
	std::atomic<bool> active;      // still loadable or marked for cleanup
	char dll_path[256];	       // or symbol name, whatever you need
};

struct VersionTable {
	std::atomic<uint32_t> latest_index; // points to the latest slot
	SharedSlot slots[8];
};

// The read path for any process:

// Atomic load current_index
// Bump refcount on that slot
// Look up the function pointer locally (each process keeps its own dlopen
// handle / GetProcAddress result cached per version) Call the function
// Decrement refcount

// The write path (whoever publishes a new DLL version):

// Find a free slot (refcount 0, not current)
// Fill in the dll path / version
// Atomic store to current_index
// Mark old slots with refcount 0 as reclaimable
