/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <rte_eal.h>
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

#include "strategy.hpp"

#define RX_RING_SIZE	1024
#define TX_RING_SIZE	1024
#define NUM_MBUFS	8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE	32

static struct alb_config config;
static uint16_t listen_port;

static ServerState server_states[ALB_MAX_BACKENDS];
static int num_servers;

struct StrategySlot {
	void *dl_handle;
	Strategy *(*create)(ServerState *, int);
	void (*destroy)(Strategy *);
	std::atomic<int32_t> in_flight{0};
};

static StrategySlot slots[2];
static std::atomic<int> active_index{0};
static std::atomic<bool> running{true};

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n", port,
		       strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
						rte_eth_dev_socket_id(port),
						NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(
		    port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	       " %02" PRIx8 " %02" PRIx8 "\n",
	       port, RTE_ETHER_ADDR_BYTES(&addr));

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

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

static Strategy *rr_create(ServerState *servers, int count)
{
	return new RoundRobinStrategy(servers, count);
}

static void rr_destroy(Strategy *s)
{
	delete s;
}

static void load_fallback_slot(StrategySlot *slot)
{
	slot->dl_handle = nullptr;
	slot->create = rr_create;
	slot->destroy = rr_destroy;
	slot->in_flight.store(0, std::memory_order_relaxed);
}

static bool load_into_slot(StrategySlot *slot, const char *path)
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

	slot->dl_handle = h;
	slot->create = cr;
	slot->destroy = de;
	slot->in_flight.store(0, std::memory_order_relaxed);
	return true;
}

static int worker_main(__rte_unused void *arg)
{
	int my_index = -1;
	Strategy *strat = nullptr;
	uint32_t pkt_seq = 0;

	while (running.load(std::memory_order_relaxed)) {
		int idx = active_index.load(std::memory_order_acquire);

		if (idx != my_index) {
			if (strat && my_index >= 0) {
				slots[my_index].destroy(strat);
				slots[my_index].in_flight.fetch_sub(
				    1, std::memory_order_release);
			}
			slots[idx].in_flight.fetch_add(
			    1, std::memory_order_acq_rel);
			strat = slots[idx].create(server_states, num_servers);
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

	if (strat && my_index >= 0) {
		slots[my_index].destroy(strat);
		slots[my_index].in_flight.fetch_sub(1,
						    std::memory_order_release);
	}

	return 0;
}

static int manager_main(__rte_unused void *arg)
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

		int old_idx = active_index.load(std::memory_order_acquire);
		int new_idx = old_idx ^ 1;

		if (!load_into_slot(&slots[new_idx],
				    "./strategies/libstrategy.so"))
			continue;

		active_index.store(new_idx, std::memory_order_release);

		while (slots[old_idx].in_flight.load(
			   std::memory_order_acquire) > 0)
			rte_pause();

		if (slots[old_idx].dl_handle)
			dlclose(slots[old_idx].dl_handle);
		slots[old_idx].dl_handle = nullptr;

		printf("reload complete\n");
	}

	close(ifd);
	return 0;
}

int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	if (argc < 3)
		rte_exit(EXIT_FAILURE,
			 "Usage: alb <config.yaml> <listen_port>\n");

	const char *config_file = argv[1];
	listen_port = htons(static_cast<uint16_t>(atoi(argv[2])));

	if (listen_port == 0)
		rte_exit(EXIT_FAILURE, "Port must be non-zero\n");

	printf("Listening for UDP packets on port %s\n", argv[2]);

	if (alb_config_load(config_file, &config) < 0)
		rte_exit(EXIT_FAILURE, "Failed to load config: %s\n",
			 config_file);

	alb_config_print(&config);

	num_servers = config.num_backends;
	for (int i = 0; i < num_servers; i++) {
		server_states[i].address = config.backends[i].ip;
		server_states[i].mac = 0;
		memcpy(&server_states[i].mac, config.backends[i].mac.addr_bytes,
		       6);
		server_states[i].active_connections = 0;
		server_states[i].weight = 1;
	}

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create(
	    "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid)
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
			 portid);

	if (!load_into_slot(&slots[0], "./strategies/libstrategy.so")) {
		printf("no strategy .so found, using built-in round-robin\n");
		load_fallback_slot(&slots[0]);
	}

	active_index.store(0, std::memory_order_relaxed);

	unsigned lcore_id;
	unsigned manager_lcore = RTE_MAX_LCORE;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (manager_lcore == RTE_MAX_LCORE) {
			manager_lcore = lcore_id;
			rte_eal_remote_launch(manager_main, nullptr, lcore_id);
		} else {
			rte_eal_remote_launch(worker_main, nullptr, lcore_id);
		}
	}

	rte_eal_mp_wait_lcore();

	rte_eal_cleanup();
	return 0;
}
