#include "strategy_loader.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_pause.h>
#include <rte_udp.h>

extern "C" {
#include "config.h"
}

extern struct alb_config config;
extern uint16_t listen_port;

HotSwapTable<StrategySlotData> strategy_table;
std::atomic<bool> running{true};
ServerState server_states[ALB_MAX_BACKENDS];
int num_servers;

class RoundRobinStrategy : public Strategy
{
	ServerState *servers;
	int count;
	uint32_t idx{0};

      public:
	RoundRobinStrategy(ServerState *s, int n) : servers(s), count(n)
	{
	}
	ServerState *select(const StrategyInput &) override
	{
		ServerState *s = &servers[idx];
		idx = (idx + 1) % static_cast<uint32_t>(count);
		return s;
	}
};

static StrategySlotData fallback_data;

static Strategy *rr_create(ServerState *servers, int count)
{
	return new RoundRobinStrategy(servers, count);
}

static void rr_destroy(Strategy *s)
{
	delete s;
}

void load_fallback_slot(StrategySlot *slot)
{
	fallback_data.create = rr_create;
	fallback_data.destroy = rr_destroy;
	slot->data = &fallback_data;
	slot->dl_handle = nullptr;
	slot->in_flight.store(0, std::memory_order_relaxed);
}

bool load_into_slot(StrategySlot *slot, const char *path)
{
	void *h = dlopen(path, RTLD_NOW);
	if (!h) {
		printf("dlopen failed: %s\n", dlerror());
		return false;
	}

	auto cr =
	    (Strategy * (*)(ServerState *, int)) dlsym(h, "create_strategy");
	auto de = (void (*)(Strategy *))dlsym(h, "destroy_strategy");

	if (!cr || !de) {
		printf("dlsym failed: %s\n", dlerror());
		dlclose(h);
		return false;
	}

	static StrategySlotData loaded_data[2];
	size_t idx = &strategy_table.slots[0] == slot ? 0 : 1;
	loaded_data[idx].create = cr;
	loaded_data[idx].destroy = de;

	slot->data = &loaded_data[idx];
	slot->dl_handle = h;
	slot->in_flight.store(0, std::memory_order_relaxed);
	return true;
}

int worker_main(__rte_unused void *arg)
{
	size_t my_index = SIZE_MAX;
	Strategy *strat = nullptr;
	uint32_t pkt_seq = 0;

	while (running.load(std::memory_order_relaxed)) {
		size_t idx =
		    strategy_table.active_index.load(std::memory_order_acquire);

		if (idx != my_index) {
			if (strat && my_index != SIZE_MAX) {
				strategy_table.slots[my_index].data->destroy(
				    strat);
				strategy_table.slots[my_index].release();
			}
			strategy_table.slots[idx].acquire();
			strat = strategy_table.slots[idx].data->create(
			    server_states, num_servers);
			my_index = idx;
		}

		uint16_t port;
		RTE_ETH_FOREACH_DEV(port)
		{
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx =
			    rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			uint16_t nb_to_tx = 0;
			for (uint16_t i = 0; i < nb_rx; i++) {
				struct rte_mbuf *m = bufs[i];
				struct rte_ether_hdr *eth_hdr =
				    rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

				if (eth_hdr->ether_type !=
				    rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
					rte_pktmbuf_free(m);
					continue;
				}

				struct rte_ipv4_hdr *ip_hdr =
				    reinterpret_cast<struct rte_ipv4_hdr *>(
					eth_hdr + 1);

				if (ip_hdr->next_proto_id != IPPROTO_UDP) {
					rte_pktmbuf_free(m);
					continue;
				}

				struct rte_udp_hdr *udp_hdr =
				    reinterpret_cast<struct rte_udp_hdr *>(
					reinterpret_cast<unsigned char *>(
					    ip_hdr) +
					(ip_hdr->version_ihl & 0x0F) * 4);

				if (udp_hdr->dst_port != listen_port) {
					rte_pktmbuf_free(m);
					continue;
				}

				StrategyInput input = {ip_hdr->src_addr ^
							   ip_hdr->dst_addr,
						       pkt_seq++};
				ServerState *ss = strat->select(input);
				int bidx = static_cast<int>(ss - server_states);

				memcpy(eth_hdr->dst_addr.addr_bytes, &ss->mac,
				       6);
				ip_hdr->dst_addr = ss->address;
				udp_hdr->dst_port = config.backends[bidx].port;

				ip_hdr->hdr_checksum = 0;
				ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
				udp_hdr->dgram_cksum = 0;

				bufs[nb_to_tx++] = m;
			}

			if (nb_to_tx == 0)
				continue;

			const uint16_t nb_tx =
			    rte_eth_tx_burst(port ^ 1, 0, bufs, nb_to_tx);
			if (unlikely(nb_tx < nb_to_tx)) {
				for (uint16_t buf = nb_tx; buf < nb_to_tx;
				     buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}

	if (strat && my_index != SIZE_MAX) {
		strategy_table.slots[my_index].data->destroy(strat);
		strategy_table.slots[my_index].release();
	}

	return 0;
}

int manager_main(__rte_unused void *arg)
{
	int ifd = inotify_init1(IN_NONBLOCK);
	inotify_add_watch(ifd, "./strategies/", IN_CLOSE_WRITE | IN_MOVED_TO);

	struct pollfd pfd = {.fd = ifd, .events = POLLIN, .revents = 0};

	while (running.load(std::memory_order_relaxed)) {
		if (poll(&pfd, 1, 500) <= 0)
			continue;

		char buf[4096];
		int len = read(ifd, buf, sizeof(buf));

		bool found = false;
		for (char *ptr = buf; ptr < buf + len;) {
			auto *ev = (struct inotify_event *)ptr;
			if (ev->len > 0 &&
			    strcmp(ev->name, "libstrategy.so") == 0)
				found = true;
			ptr += sizeof(struct inotify_event) + ev->len;
		}

		if (!found)
			continue;

		printf("new strategy detected, reloading...\n");

		StrategySlot &new_slot = strategy_table.inactive();

		if (!load_into_slot(&new_slot, "./strategies/libstrategy.so"))
			continue;

		StrategySlot &old_slot = strategy_table.active();
		strategy_table.swap();

		while (!old_slot.idle())
			rte_pause();

		if (old_slot.dl_handle)
			dlclose(old_slot.dl_handle);
		old_slot.dl_handle = nullptr;

		printf("reload complete\n");
	}

	close(ifd);
	return 0;
}
