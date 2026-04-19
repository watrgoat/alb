/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <csignal>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

extern "C" {
#include "config.h"
}

#include "strategy_loader.hpp"

#define RX_RING_SIZE	1024
#define TX_RING_SIZE	1024
#define NUM_MBUFS	8191
#define MBUF_CACHE_SIZE 250

struct alb_config config;
uint16_t listen_port;

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool,
			    uint16_t nb_queues)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = nb_queues, tx_rings = nb_queues;
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

	// With >1 RX queue, enable RSS over IPv4+UDP so the generator's
	// per-packet varying src_port spreads traffic across workers.
	if (nb_queues > 1) {
		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
		port_conf.rx_adv_conf.rss_conf.rss_hf =
		    (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP) &
		    dev_info.flow_type_rss_offloads;
	}

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

static void sig_handler(int)
{
	extern std::atomic<bool> running;
	running.store(false, std::memory_order_relaxed);
}

int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	// Make stdout unbuffered so logs survive SIGINT/kill.
	setvbuf(stdout, nullptr, _IONBF, 0);
	setvbuf(stderr, nullptr, _IONBF, 0);

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
		server_states[i].weight = config.backends[i].weight;
	}

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	// Count worker lcores (all workers minus one reserved for manager) so
	// we can size the NIC's RX/TX rings accordingly.
	unsigned total_workers = 0;
	{
		unsigned lc;
		RTE_LCORE_FOREACH_WORKER(lc) total_workers++;
	}
	if (total_workers < 2)
		rte_exit(EXIT_FAILURE,
			 "Need at least 3 lcores (main + manager + >=1 worker); "
			 "got %u total.\n",
			 rte_lcore_count());
	const uint16_t num_fwd_workers =
	    static_cast<uint16_t>(total_workers - 1);
	printf("Launching %u forwarding worker(s) with %u RX/TX queues per port\n",
	       num_fwd_workers, num_fwd_workers);

	// Size the pool to comfortably cover RX+TX descriptors per queue across
	// all ports, plus per-lcore mbuf cache and burst headroom. Undersizing
	// starves RX DMA and shows up as `imissed`.
	uint32_t pool_size =
	    nb_ports * num_fwd_workers *
	    (RX_RING_SIZE + TX_RING_SIZE + MBUF_CACHE_SIZE + 1024);
	if (pool_size < NUM_MBUFS * nb_ports)
		pool_size = NUM_MBUFS * nb_ports;
	printf("mbuf pool size: %u\n", pool_size);
	mbuf_pool = rte_pktmbuf_pool_create(
	    "MBUF_POOL", pool_size, MBUF_CACHE_SIZE, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid)
	if (port_init(portid, mbuf_pool, num_fwd_workers) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
			 portid);

	if (!load_into_slot(&strategy_table.slots[0],
			    "./strategies/libstrategy.so")) {
		printf("no strategy .so found, using built-in round-robin\n");
		load_fallback_slot(&strategy_table.slots[0]);
	}

	strategy_table.active_index.store(0, std::memory_order_relaxed);

	unsigned lcore_id;
	unsigned manager_lcore = RTE_MAX_LCORE;
	unsigned num_workers = 0;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (manager_lcore == RTE_MAX_LCORE) {
			manager_lcore = lcore_id;
			rte_eal_remote_launch(manager_main, nullptr, lcore_id);
		} else {
			// Pass per-worker queue id (0..num_fwd_workers-1) via arg
			uintptr_t qid = num_workers;
			rte_eal_remote_launch(
			    worker_main, reinterpret_cast<void *>(qid),
			    lcore_id);
			num_workers++;
		}
	}

	if (num_workers == 0)
		rte_exit(EXIT_FAILURE,
			 "No forwarding worker launched. Need at least 3 lcores "
			 "(main + manager + >=1 worker); got %u.\n",
			 rte_lcore_count());

	// Clean shutdown on SIGINT/SIGTERM (otherwise workers spin forever and
	// buffered stdout never flushes).
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Main-thread stats loop: every second, print per-port ipackets/opackets
	// deltas, plus per-RX-queue distribution so uneven RSS is visible.
	struct rte_eth_stats prev[RTE_MAX_ETHPORTS] = {};
	for (uint16_t p = 0; p < rte_eth_dev_count_avail(); p++)
		rte_eth_stats_get(p, &prev[p]);

	while (running.load(std::memory_order_relaxed)) {
		sleep(1);
		for (uint16_t p = 0; p < rte_eth_dev_count_avail(); p++) {
			struct rte_eth_stats cur;
			if (rte_eth_stats_get(p, &cur) != 0)
				continue;
			uint64_t rx = cur.ipackets - prev[p].ipackets;
			uint64_t tx = cur.opackets - prev[p].opackets;
			uint64_t imiss = cur.imissed - prev[p].imissed;
			uint64_t ierr = cur.ierrors - prev[p].ierrors;
			printf("port %u  rx %" PRIu64 " pps  tx %" PRIu64
			       " pps  imissed %" PRIu64 "  ierrors %" PRIu64,
			       p, rx, tx, imiss, ierr);
			// per-queue RX breakdown (only interesting on the
			// ingress port — RSS-spread queues; TX queues are
			// 1:1 with workers so they mirror tx counter).
			if (rx > 0) {
				printf("  [");
				for (uint16_t q = 0;
				     q < num_fwd_workers &&
				     q < RTE_ETHDEV_QUEUE_STAT_CNTRS;
				     q++) {
					uint64_t qrx = cur.q_ipackets[q] -
						       prev[p].q_ipackets[q];
					printf("%s%" PRIu64, q ? "," : "",
					       qrx);
				}
				printf("]");
			}
			printf("\n");
			prev[p] = cur;
		}
	}

	rte_eal_mp_wait_lcore();

	rte_eal_cleanup();
	return 0;
}
