#include "metrics.hpp"

#include <cstdio>
#include <sstream>

MetricsCollector::MetricsCollector(int n)
    : counters_(n), last_sent_(n, 0), last_missed_(n, 0)
{
}

void MetricsCollector::record_sent(int bidx, uint64_t n)
{
	counters_[bidx].packets_sent.fetch_add(n, std::memory_order_relaxed);
}

void MetricsCollector::record_missed(int bidx, uint64_t n)
{
	counters_[bidx].packets_missed.fetch_add(n, std::memory_order_relaxed);
}

void MetricsCollector::set_ip(int bidx, uint32_t ip)
{
	counters_[bidx].ip = ip;
}

void MetricsCollector::set_capacity_hint(int bidx, uint32_t pps)
{
	counters_[bidx].capacity_hint = pps;
}

void MetricsCollector::set_active_connections(int bidx, uint32_t n)
{
	counters_[bidx].active_connections = n;
}

MetricsSnapshot MetricsCollector::snapshot(uint64_t now_sec, double window_sec)
{
	MetricsSnapshot snap;
	snap.timestamp_sec = now_sec;
	snap.window_sec = window_sec;
	snap.backends.reserve(counters_.size());

	for (size_t i = 0; i < counters_.size(); i++) {
		uint64_t sent =
		    counters_[i].packets_sent.load(std::memory_order_relaxed);
		uint64_t missed =
		    counters_[i].packets_missed.load(std::memory_order_relaxed);

		BackendSample s;
		s.backend_idx = static_cast<int>(i);
		s.ip = counters_[i].ip;
		s.packets_sent = sent - last_sent_[i];
		s.packets_missed = missed - last_missed_[i];
		s.active_connections = counters_[i].active_connections;
		s.capacity_hint = counters_[i].capacity_hint;
		snap.backends.push_back(s);

		last_sent_[i] = sent;
		last_missed_[i] = missed;
	}

	return snap;
}

static void fmt_u32_ip(std::ostringstream &os, uint32_t ip)
{
	os << ((ip >> 24) & 0xff) << '.' << ((ip >> 16) & 0xff) << '.'
	   << ((ip >> 8) & 0xff) << '.' << (ip & 0xff);
}

std::string MetricsSnapshot::to_json() const
{
	std::ostringstream os;
	os << "{\"timestamp\":" << timestamp_sec
	   << ",\"window_sec\":" << window_sec << ",\"backends\":[";
	for (size_t i = 0; i < backends.size(); i++) {
		const auto &b = backends[i];
		if (i)
			os << ',';
		os << "{\"idx\":" << b.backend_idx << ",\"ip\":\"";
		fmt_u32_ip(os, b.ip);
		os << "\",\"packets_sent\":" << b.packets_sent
		   << ",\"packets_missed\":" << b.packets_missed
		   << ",\"active_connections\":" << b.active_connections
		   << ",\"capacity_hint\":" << b.capacity_hint << '}';
	}
	os << "]}";
	return os.str();
}

std::string MetricsSnapshot::to_csv_rows() const
{
	std::ostringstream os;
	for (const auto &b : backends) {
		os << timestamp_sec << ',' << b.backend_idx << ',';
		fmt_u32_ip(os, b.ip);
		os << ',' << b.packets_sent << ',' << b.packets_missed << ','
		   << b.capacity_hint << '\n';
	}
	return os.str();
}
