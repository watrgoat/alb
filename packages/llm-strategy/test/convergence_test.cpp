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

struct ConvergenceResult {
	std::vector<PerSecondRow> rows;
	bool passed{true};
	std::vector<std::string> failures;
};

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
			ServerState *ss = strat->select(in);
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
			auto weights = gen.compute_weights(snap);
			for (int i = 0; i < cfg.n_backends; i++)
				servers[i].weight = weights[i];
			// toggle slot to exercise the swap path. both slots
			// hold the same create/destroy pair here (weights live
			// on ServerState).
			table.swap();
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
	bool in_test_mode = false;

	for (int i = 1; i < argc; i++) {
		std::string a = argv[i];
		if (a == "--csv" && i + 1 < argc)
			csv_path = argv[++i];
		else if (a == "--markers" && i + 1 < argc)
			markers_path = argv[++i];
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

	if (!res.passed) {
		for (const auto &m : res.failures)
			fprintf(stderr, "FAIL: %s\n", m.c_str());
		return in_test_mode ? 1 : 1;
	}

	fprintf(stdout, "convergence test: PASS (%zu sample rows)\n",
		res.rows.size());
	return 0;
}
