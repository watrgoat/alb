#pragma once

#include "metrics.hpp"
#include <cstdint>
#include <string>
#include <vector>

// deterministic stub: maintains per-backend capacity estimate and emits
// WeightedStrategy weights proportional to estimated capacity. used by the
// convergence test (offline, no network) and as fallback when
// ANTHROPIC_API_KEY is unset.
class StubGenerator
{
	std::vector<double> cap_est_;
	bool initialized_{false};

      public:
	// snap: delta counters for the window just elapsed.
	// returns one weight per backend (>=1).
	std::vector<uint32_t> compute_weights(const MetricsSnapshot &snap);

	// emit a self-contained C++ source implementing Strategy with the
	// given baked-in weights. compatible with the existing ABI.
	static std::string emit_source(const std::vector<uint32_t> &weights);
};
