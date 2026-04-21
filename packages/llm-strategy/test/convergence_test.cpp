// in-process convergence harness. simulates 3 backends with per-backend
// processing_capacity_pps; routes a fixed aggregate rate through the current
// Strategy (hot-swapped via HotSwapTable); every K seconds re-computes
// weights from MetricsSnapshot using StubGenerator and swaps.
//
// writes per-second per-backend CSV rows; if run as a cc_test, also asserts
// convergence after each capacity change.

#include "metrics.hpp"
#include "stub_generator.hpp"
#include "strategy.hpp"
#include "table.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

namespace {

// mirror of src/strategy_loader.hpp's StrategySlotData. kept private to avoid
// pulling DPDK-flavored loader headers into this offline unit test.
struct StrategySlotData {
	Strategy *(*create)(ServerState *, int);
	void (*destroy)(Strategy *);
};

// splitmix32-style avalanche mixer. the simulator feeds sequential packet
// indices as the "hash" input to Strategy; a raw p*K has enough rank-1
// lattice bias to skew 300-packet windows by several percent, which breaks
// per-backend ratio checks for no reason related to the generator logic.
inline uint32_t mix_hash(uint32_t x)
{
	x = (x ^ (x >> 16)) * 0x7FEB352Du;
	x = (x ^ (x >> 15)) * 0x846CA68Bu;
	return x ^ (x >> 16);
}

class WeightedStrategy : public Strategy
{
	ServerState *servers_;
	int count_;

      public:
	WeightedStrategy(ServerState *s, int n) : servers_(s), count_(n)
	{
	}
	ServerState *select(const StrategyInput &in) override
	{
		uint32_t total = 0;
		for (int i = 0; i < count_; i++)
			total += servers_[i].weight;
		if (!total)
			return &servers_[0];
		uint32_t target = in.packet_hash % total;
		uint32_t cum = 0;
		for (int i = 0; i < count_; i++) {
			cum += servers_[i].weight;
			if (target < cum)
				return &servers_[i];
		}
		return &servers_[count_ - 1];
	}
};

Strategy *ws_create(ServerState *s, int n)
{
	return new WeightedStrategy(s, n);
}
void ws_destroy(Strategy *s)
{
	delete s;
}

struct ConvergenceConfig {
	int n_backends = 3;
	// bumped from the PROMPT.md example (300) to reduce the hash-%-total
	// rank-1 lattice variance. 3000 keeps a 2σ backend ratio deviation
	// comfortably inside [0.9, 1.1] for every phase. capacities scale
	// 10x accordingly so ratios in the scenario remain identical.
	uint32_t total_rate_pps = 3000;
	int duration_sec = 180;
	int generate_every = 5;
	int check_after_sec = 20;
	double ratio_low = 0.9;
	double ratio_high = 1.1;
	double total_miss_budget = 0.05;

	// latency budgets. these run in the simulator — no network — so they
	// measure code-path overhead only. budgets are intentionally loose so
	// the test doesn't flake on loaded CI hosts / sanitizer builds, but
	// tight enough to catch an accidental O(n^2) or alloc-in-hot-path
	// regression.
	double select_p99_ns_budget = 5000.0;     // per-packet select()
	double compute_weights_p99_ns_budget = 1e6;   // per-cycle (1 ms)
	double swap_max_ns_budget = 500000.0;     // per-cycle swap (500 us)
};

struct CapChange {
	uint64_t t_sec;
	std::vector<uint32_t> caps;
};

struct PerSecondRow {
	int t;
	int bidx;
	uint32_t ip;
	uint64_t sent;
	uint64_t missed;
	uint32_t cap;
};

struct LatencyStats {
	// per-packet select() latency across the whole run, nanoseconds.
	std::vector<uint64_t> select_ns;
	// per-cycle compute_weights() latency, nanoseconds.
	std::vector<uint64_t> compute_weights_ns;
	// per-cycle HotSwapTable::swap() latency, nanoseconds.
	std::vector<uint64_t> swap_ns;
};

struct LatencySummary {
	double select_p50_ns{0}, select_p95_ns{0}, select_p99_ns{0};
	uint64_t select_max_ns{0};
	double compute_weights_p50_ns{0}, compute_weights_p99_ns{0};
	uint64_t compute_weights_max_ns{0};
	double swap_p50_ns{0}, swap_p99_ns{0};
	uint64_t swap_max_ns{0};
	size_t n_select_samples{0};
	size_t n_cycle_samples{0};
};

struct ConvergenceResult {
	std::vector<PerSecondRow> rows;
	bool passed{true};
	std::vector<std::string> failures;
	LatencyStats latency;
	LatencySummary latency_summary;
};

double percentile_ns(std::vector<uint64_t> &xs, double q)
{
	if (xs.empty())
		return 0.0;
	size_t k = static_cast<size_t>(q * (xs.size() - 1));
	std::nth_element(xs.begin(), xs.begin() + k, xs.end());
	return static_cast<double>(xs[k]);
}

LatencySummary summarize_latency(LatencyStats stats)
{
	LatencySummary s;
	s.n_select_samples = stats.select_ns.size();
	s.n_cycle_samples = stats.compute_weights_ns.size();
	if (!stats.select_ns.empty()) {
		s.select_max_ns = *std::max_element(stats.select_ns.begin(),
						    stats.select_ns.end());
		// nth_element mutates; percentile_ns takes by reference so the
		// three calls compose cheaply on the same buffer.
		s.select_p50_ns = percentile_ns(stats.select_ns, 0.50);
		s.select_p95_ns = percentile_ns(stats.select_ns, 0.95);
		s.select_p99_ns = percentile_ns(stats.select_ns, 0.99);
	}
	if (!stats.compute_weights_ns.empty()) {
		s.compute_weights_max_ns =
		    *std::max_element(stats.compute_weights_ns.begin(),
				      stats.compute_weights_ns.end());
		s.compute_weights_p50_ns =
		    percentile_ns(stats.compute_weights_ns, 0.50);
		s.compute_weights_p99_ns =
		    percentile_ns(stats.compute_weights_ns, 0.99);
	}
	if (!stats.swap_ns.empty()) {
		s.swap_max_ns = *std::max_element(stats.swap_ns.begin(),
						  stats.swap_ns.end());
		s.swap_p50_ns = percentile_ns(stats.swap_ns, 0.50);
		s.swap_p99_ns = percentile_ns(stats.swap_ns, 0.99);
	}
	return s;
}

ConvergenceResult run_simulation(const ConvergenceConfig &cfg,
				 const std::vector<CapChange> &schedule)
{
	ConvergenceResult out;

	std::vector<ServerState> servers(cfg.n_backends);
	std::vector<uint32_t> caps(cfg.n_backends, 0);
	for (int i = 0; i < cfg.n_backends; i++) {
		servers[i].address = 0xC0A80001u + i;
		servers[i].mac = 0;
		servers[i].active_connections = 0;
		servers[i].weight = 1;
	}

	HotSwapTable<StrategySlotData> table;
	StrategySlotData slot_data[2];
	slot_data[0].create = ws_create;
	slot_data[0].destroy = ws_destroy;
	slot_data[1] = slot_data[0];
	table.slots[0].data = &slot_data[0];
	table.slots[1].data = &slot_data[1];

	MetricsCollector metrics(cfg.n_backends);
	for (int i = 0; i < cfg.n_backends; i++)
		metrics.set_ip(i, servers[i].address);

	StubGenerator gen;

	for (int t = 0; t < cfg.duration_sec; t++) {
		for (const auto &ch : schedule) {
			if (static_cast<uint64_t>(t) == ch.t_sec) {
				for (int i = 0; i < cfg.n_backends; i++) {
					caps[i] = ch.caps[i];
					metrics.set_capacity_hint(i, caps[i]);
				}
			}
		}

		// route 1 second of traffic through the current strategy.
		Slot<StrategySlotData> &slot = table.active();
		slot.acquire();
		Strategy *strat = slot.data->create(servers.data(),
						    cfg.n_backends);

		std::vector<uint32_t> sent(cfg.n_backends, 0);
		for (uint32_t p = 0; p < cfg.total_rate_pps; p++) {
			StrategyInput in{
			    mix_hash(static_cast<uint32_t>(t) * 0x9E3779B1u + p),
			    p};
			// per-packet select() latency. steady_clock::now() is
			// ~20-30ns on modern x86, so for very short select()
			// paths we're partly measuring the clock itself — that
			// sets the noise floor. we record the measured delta
			// directly; the p99 budget accounts for this floor.
			auto t0 = std::chrono::steady_clock::now();
			ServerState *ss = strat->select(in);
			auto t1 = std::chrono::steady_clock::now();
			out.latency.select_ns.push_back(
			    static_cast<uint64_t>(
				std::chrono::duration_cast<
				    std::chrono::nanoseconds>(t1 - t0)
				    .count()));
			int bidx =
			    static_cast<int>(ss - servers.data());
			sent[bidx]++;
		}

		slot.data->destroy(strat);
		slot.release();

		std::vector<uint32_t> miss(cfg.n_backends, 0);
		for (int i = 0; i < cfg.n_backends; i++) {
			miss[i] =
			    sent[i] > caps[i] ? sent[i] - caps[i] : 0;
			metrics.record_sent(i, sent[i]);
			metrics.record_missed(i, miss[i]);

			PerSecondRow row;
			row.t = t;
			row.bidx = i;
			row.ip = servers[i].address;
			row.sent = sent[i];
			row.missed = miss[i];
			row.cap = caps[i];
			out.rows.push_back(row);
		}

		// run the generator every K seconds. in the real system this
		// would compile+install; in the unit test we short-circuit and
		// update server_states[].weight + HotSwapTable::swap directly.
		if ((t + 1) % cfg.generate_every == 0) {
			MetricsSnapshot snap = metrics.snapshot(
			    static_cast<uint64_t>(t),
			    static_cast<double>(cfg.generate_every));
			auto cw_t0 = std::chrono::steady_clock::now();
			auto weights = gen.compute_weights(snap);
			auto cw_t1 = std::chrono::steady_clock::now();
			out.latency.compute_weights_ns.push_back(
			    static_cast<uint64_t>(
				std::chrono::duration_cast<
				    std::chrono::nanoseconds>(cw_t1 - cw_t0)
				    .count()));

			for (int i = 0; i < cfg.n_backends; i++)
				servers[i].weight = weights[i];
			// toggle slot to exercise the swap path. both slots
			// hold the same create/destroy pair here (weights live
			// on ServerState).
			auto sw_t0 = std::chrono::steady_clock::now();
			table.swap();
			auto sw_t1 = std::chrono::steady_clock::now();
			out.latency.swap_ns.push_back(static_cast<uint64_t>(
			    std::chrono::duration_cast<
				std::chrono::nanoseconds>(sw_t1 - sw_t0)
				.count()));
		}
	}

	// assertions:
	// for each capacity change at t=ts, after check_after_sec elapsed,
	// per-backend sent/cap must be within [ratio_low, ratio_high].
	// also total miss rate over the check window must be < total_miss_budget.
	for (size_t ci = 0; ci < schedule.size(); ci++) {
		uint64_t ts = schedule[ci].t_sec;
		int check_t = static_cast<int>(ts) + cfg.check_after_sec;
		if (check_t >= cfg.duration_sec)
			continue;
		// check using the 1-second window ending at check_t-1.
		std::vector<uint64_t> w_sent(cfg.n_backends, 0);
		std::vector<uint64_t> w_miss(cfg.n_backends, 0);
		std::vector<uint32_t> w_cap(cfg.n_backends, 0);
		for (const auto &r : out.rows) {
			if (r.t == check_t - 1) {
				w_sent[r.bidx] = r.sent;
				w_miss[r.bidx] = r.missed;
				w_cap[r.bidx] = r.cap;
			}
		}
		for (int i = 0; i < cfg.n_backends; i++) {
			if (!w_cap[i])
				continue;
			double ratio = static_cast<double>(w_sent[i]) /
				       static_cast<double>(w_cap[i]);
			if (ratio < cfg.ratio_low ||
			    ratio > cfg.ratio_high) {
				char buf[256];
				snprintf(buf, sizeof(buf),
					 "t=%d backend %d sent=%lu cap=%u "
					 "ratio=%.3f out of [%.2f,%.2f]",
					 check_t - 1, i,
					 static_cast<unsigned long>(w_sent[i]),
					 w_cap[i], ratio, cfg.ratio_low,
					 cfg.ratio_high);
				out.failures.emplace_back(buf);
				out.passed = false;
			}
		}
	}

	// total miss rate over the entire test run. transients after each
	// capacity change contribute; with 4 shifts and ~15s of recovery per
	// shift, we expect roughly 3-4% miss end-to-end.
	uint64_t tot_sent = 0, tot_miss = 0;
	for (const auto &r : out.rows) {
		tot_sent += r.sent;
		tot_miss += r.missed;
	}
	double mr = tot_sent ? static_cast<double>(tot_miss) /
				static_cast<double>(tot_sent)
			     : 0.0;
	if (mr > cfg.total_miss_budget) {
		char buf[256];
		snprintf(buf, sizeof(buf),
			 "total miss rate %.3f > budget %.3f "
			 "(sent=%lu missed=%lu)",
			 mr, cfg.total_miss_budget,
			 static_cast<unsigned long>(tot_sent),
			 static_cast<unsigned long>(tot_miss));
		out.failures.emplace_back(buf);
		out.passed = false;
	}

	// latency assertions. summarize_latency mutates its argument (nth_element
	// shuffles the buffers), so pass a copy so the raw samples in
	// out.latency stay usable for any downstream CSV dump.
	out.latency_summary = summarize_latency(out.latency);
	const LatencySummary &ls = out.latency_summary;
	if (ls.select_p99_ns > cfg.select_p99_ns_budget) {
		char buf[256];
		snprintf(buf, sizeof(buf),
			 "select() p99 latency %.0f ns > budget %.0f ns "
			 "(p50=%.0f p95=%.0f max=%lu over %zu samples)",
			 ls.select_p99_ns, cfg.select_p99_ns_budget,
			 ls.select_p50_ns, ls.select_p95_ns,
			 static_cast<unsigned long>(ls.select_max_ns),
			 ls.n_select_samples);
		out.failures.emplace_back(buf);
		out.passed = false;
	}
	if (ls.compute_weights_p99_ns > cfg.compute_weights_p99_ns_budget) {
		char buf[256];
		snprintf(buf, sizeof(buf),
			 "compute_weights() p99 latency %.0f ns > budget %.0f "
			 "ns (p50=%.0f max=%lu over %zu cycles)",
			 ls.compute_weights_p99_ns,
			 cfg.compute_weights_p99_ns_budget,
			 ls.compute_weights_p50_ns,
			 static_cast<unsigned long>(ls.compute_weights_max_ns),
			 ls.n_cycle_samples);
		out.failures.emplace_back(buf);
		out.passed = false;
	}
	if (static_cast<double>(ls.swap_max_ns) > cfg.swap_max_ns_budget) {
		char buf[256];
		snprintf(buf, sizeof(buf),
			 "HotSwapTable::swap() max latency %lu ns > budget "
			 "%.0f ns (p50=%.0f p99=%.0f over %zu cycles)",
			 static_cast<unsigned long>(ls.swap_max_ns),
			 cfg.swap_max_ns_budget, ls.swap_p50_ns,
			 ls.swap_p99_ns, ls.n_cycle_samples);
		out.failures.emplace_back(buf);
		out.passed = false;
	}

	return out;
}

void write_csv(const ConvergenceResult &res, const std::string &path)
{
	std::ofstream os(path);
	os << "timestamp,backend_idx,ip,packets_sent,packets_missed,capacity\n";
	for (const auto &r : res.rows) {
		os << r.t << ',' << r.bidx << ',' << ((r.ip >> 24) & 0xff)
		   << '.' << ((r.ip >> 16) & 0xff) << '.'
		   << ((r.ip >> 8) & 0xff) << '.' << (r.ip & 0xff) << ','
		   << r.sent << ',' << r.missed << ',' << r.cap << '\n';
	}
}

void write_markers(const std::vector<CapChange> &schedule,
		   const std::string &path)
{
	std::ofstream os(path);
	os << "timestamp,cap0,cap1,cap2\n";
	for (const auto &c : schedule) {
		os << c.t_sec;
		for (auto v : c.caps)
			os << ',' << v;
		os << '\n';
	}
}

} // namespace

int main(int argc, char **argv)
{
	std::string csv_path;
	std::string markers_path;
	std::string latency_path;
	bool in_test_mode = false;

	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		if (a == "--csv" && i + 1 < argc)
			csv_path = argv[++i];
		else if (a == "--markers" && i + 1 < argc)
			markers_path = argv[++i];
		else if (a == "--latency-csv" && i + 1 < argc)
			latency_path = argv[++i];
		else if (a == "--test")
			in_test_mode = true;
	}

	// only write CSV when explicitly requested; cc_test mode stays silent
	// to avoid triggering bazel's outputs.zip archiving step (which
	// requires `zip` on the host).

	ConvergenceConfig cfg;
	// capacity schedule (scaled 10x from the PROMPT.md example to match
	// the 10x'd traffic rate; ratios 1:1:1 → 1:2:3 → 3:1:2 → 1:1:1 are
	// preserved).
	std::vector<CapChange> schedule = {
	    {0, {1000, 1000, 1000}},
	    {30, {500, 1000, 1500}},
	    {90, {1500, 500, 1000}},
	    {150, {1000, 1000, 1000}},
	};

	ConvergenceResult res = run_simulation(cfg, schedule);

	if (!csv_path.empty())
		write_csv(res, csv_path);
	if (!markers_path.empty())
		write_markers(schedule, markers_path);
	if (!latency_path.empty()) {
		std::ofstream os(latency_path);
		os << "metric,p50_ns,p95_ns,p99_ns,max_ns,samples\n";
		const LatencySummary &ls = res.latency_summary;
		os << "select," << ls.select_p50_ns << ',' << ls.select_p95_ns
		   << ',' << ls.select_p99_ns << ',' << ls.select_max_ns << ','
		   << ls.n_select_samples << '\n';
		os << "compute_weights," << ls.compute_weights_p50_ns << ",,"
		   << ls.compute_weights_p99_ns << ','
		   << ls.compute_weights_max_ns << ',' << ls.n_cycle_samples
		   << '\n';
		os << "swap," << ls.swap_p50_ns << ",," << ls.swap_p99_ns << ','
		   << ls.swap_max_ns << ',' << ls.n_cycle_samples << '\n';
	}

	if (!res.passed) {
		for (const auto &m : res.failures)
			fprintf(stderr, "FAIL: %s\n", m.c_str());
		return in_test_mode ? 1 : 1;
	}

	const LatencySummary &ls = res.latency_summary;
	fprintf(stdout,
		"convergence test: PASS (%zu sample rows)\n"
		"  select():         p50=%.0f ns  p95=%.0f ns  p99=%.0f ns  "
		"max=%lu ns  (n=%zu)\n"
		"  compute_weights():p50=%.0f ns  p99=%.0f ns  max=%lu ns  "
		"(n=%zu)\n"
		"  swap():           p50=%.0f ns  p99=%.0f ns  max=%lu ns  "
		"(n=%zu)\n",
		res.rows.size(), ls.select_p50_ns, ls.select_p95_ns,
		ls.select_p99_ns, static_cast<unsigned long>(ls.select_max_ns),
		ls.n_select_samples, ls.compute_weights_p50_ns,
		ls.compute_weights_p99_ns,
		static_cast<unsigned long>(ls.compute_weights_max_ns),
		ls.n_cycle_samples, ls.swap_p50_ns, ls.swap_p99_ns,
		static_cast<unsigned long>(ls.swap_max_ns), ls.n_cycle_samples);
	return 0;
}
