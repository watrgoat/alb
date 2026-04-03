/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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
		server_states[i].weight = config.backends[i].weight;
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

	if (!load_into_slot(&strategy_table.slots[0],
			    "./strategies/libstrategy.so")) {
		printf("no strategy .so found, using built-in round-robin\n");
		load_fallback_slot(&strategy_table.slots[0]);
	}

	strategy_table.active_index.store(0, std::memory_order_relaxed);

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
