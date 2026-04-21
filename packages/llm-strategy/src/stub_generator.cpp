#include "stub_generator.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>

std::vector<uint32_t>
StubGenerator::compute_weights(const MetricsSnapshot &snap)
{
	const size_t n = snap.backends.size();
	if (!initialized_ || cap_est_.size() != n) {
		cap_est_.assign(n, 100.0);
		initialized_ = true;
	}

	// water-filling: when some backends drop, reassign the dropped load
	// onto the non-dropping backends proportional to their current
	// estimated capacity. total weight is preserved across a cycle, so
	// the "healthy" backends grow at the same rate that the saturated
	// ones shrink — this converges symmetrically in both directions,
	// unlike a local per-backend snap-down-vs-slow-grow rule.
	uint64_t total_miss = 0;
	double total_good_cap = 0.0;
	int n_good = 0;
	for (size_t i = 0; i < n; i++) {
		total_miss += snap.backends[i].packets_missed;
		if (snap.backends[i].packets_missed == 0) {
			total_good_cap += cap_est_[i];
			n_good++;
		}
	}

	if (total_miss == 0) {
		// no drops anywhere. probe all weights up 5% and also track
		// observed throughput from below so a collapse in a sibling
		// backend doesn't leave us with stale overestimates.
		for (size_t i = 0; i < n; i++) {
			double s = static_cast<double>(
			    snap.backends[i].packets_sent);
			cap_est_[i] = std::max(cap_est_[i] * 1.05, s);
		}
	} else if (n_good > 0 && total_good_cap > 0.0) {
		double miss_total = static_cast<double>(total_miss);
		for (size_t i = 0; i < n; i++) {
			double m = static_cast<double>(
			    snap.backends[i].packets_missed);
			if (m > 0) {
				cap_est_[i] =
				    std::max(1.0, cap_est_[i] - m);
			} else {
				cap_est_[i] += miss_total * cap_est_[i] /
					       total_good_cap;
			}
		}
	} else {
		// every backend dropped — all weights over-allocated.
		// snap each to its observed ceiling.
		for (size_t i = 0; i < n; i++) {
			double eff = static_cast<double>(
					 snap.backends[i].packets_sent) -
				     static_cast<double>(
					 snap.backends[i].packets_missed);
			cap_est_[i] = std::max(1.0, eff);
		}
	}

	std::vector<uint32_t> w(n);
	for (size_t i = 0; i < n; i++) {
		double v = std::round(cap_est_[i]);
		if (v < 1.0)
			v = 1.0;
		w[i] = static_cast<uint32_t>(v);
	}
	return w;
}

std::string StubGenerator::emit_source(const std::vector<uint32_t> &weights)
{
	std::ostringstream os;
	os << "#include \"strategy.hpp\"\n";
	os << "namespace {\n";
	os << "constexpr uint32_t kWeights[] = {";
	for (size_t i = 0; i < weights.size(); i++) {
		if (i)
			os << ',';
		os << weights[i] << 'u';
	}
	os << "};\n";
	os << "constexpr int kCount = " << weights.size() << ";\n";
	os << "class GenStrategy : public Strategy {\n"
	      "  ServerState *servers_;\n"
	      "  int count_;\n"
	      "  uint32_t total_;\n"
	      " public:\n"
	      "  GenStrategy(ServerState *s, int n) : servers_(s), count_(n), total_(0) {\n"
	      "    for (int i = 0; i < n && i < kCount; i++) total_ += kWeights[i];\n"
	      "    if (!total_) total_ = 1;\n"
	      "  }\n"
	      "  ServerState *select(const StrategyInput &in) override {\n"
	      "    uint32_t t = in.packet_hash % total_;\n"
	      "    uint32_t c = 0;\n"
	      "    for (int i = 0; i < count_ && i < kCount; i++) {\n"
	      "      c += kWeights[i];\n"
	      "      if (t < c) return &servers_[i];\n"
	      "    }\n"
	      "    return &servers_[count_ - 1];\n"
	      "  }\n"
	      "};\n"
	      "}\n";
	os << "extern \"C\" Strategy *create_strategy(ServerState *s, int n) {\n"
	      "  return new GenStrategy(s, n);\n"
	      "}\n";
	os << "extern \"C\" void destroy_strategy(Strategy *s) { delete s; }\n";
	return os.str();
}
