#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

// per-backend rolling counters. writers are worker TX threads (one per backend
// in the simple case); reader is the snapshotter running on the manager lcore.
// relaxed ordering is fine for coarse aggregates.
struct BackendCounters {
	std::atomic<uint64_t> packets_sent{0};
	std::atomic<uint64_t> packets_missed{0};
	uint32_t ip{0};
	uint32_t capacity_hint{0};
	uint32_t active_connections{0};
};

struct BackendSample {
	int backend_idx;
	uint32_t ip;
	uint64_t packets_sent;
	uint64_t packets_missed;
	uint32_t active_connections;
	uint32_t capacity_hint;
};

struct MetricsSnapshot {
	uint64_t timestamp_sec{0};
	double window_sec{0.0};
	std::vector<BackendSample> backends;

	// json for the LLM prompt; csv for the plot driver.
	std::string to_json() const;
	std::string to_csv_rows() const;
};

class MetricsCollector
{
	std::vector<BackendCounters> counters_;
	std::vector<uint64_t> last_sent_;
	std::vector<uint64_t> last_missed_;

      public:
	explicit MetricsCollector(int num_backends);

	void record_sent(int bidx, uint64_t n = 1);
	void record_missed(int bidx, uint64_t n);
	void set_ip(int bidx, uint32_t ip);
	void set_capacity_hint(int bidx, uint32_t pps);
	void set_active_connections(int bidx, uint32_t n);

	// delta-since-last-call snapshot. window_sec is the caller-reported
	// elapsed wall time (used by downstream rate math; not recomputed here).
	MetricsSnapshot snapshot(uint64_t now_sec, double window_sec);

	int size() const
	{
		return static_cast<int>(counters_.size());
	}
};
