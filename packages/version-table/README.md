# version-table

Lock-free versioning table for hot-swapping shared libraries across processes. Uses atomic operations and reference counting to safely update function pointers without blocking readers.

## Build

```bash
bazel build //packages/version-table:version-table
```

## Usage

```cpp
#include "table.hpp"

// Read path: load index → bump refcount → call function → decrement refcount
// Write path: find free slot → fill dll path → atomic store index → reclaim old slots
```
