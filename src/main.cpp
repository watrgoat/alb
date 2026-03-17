/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

extern "C" {
#include "config.h"
}

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static struct alb_config config;
static uint16_t listen_port;
static uint16_t rr_index;

static inline struct alb_backend *
next_backend()
{
	struct alb_backend *b = &config.backends[rr_index];
	rr_index = (rr_index + 1) % config.num_backends;
	return b;
}

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
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

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static __rte_noreturn void
lcore_main()
{
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						static_cast<int>(rte_socket_id()))
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			uint16_t nb_to_tx = 0;
			for (uint16_t i = 0; i < nb_rx; i++) {
				struct rte_mbuf *m = bufs[i];
				struct rte_ether_hdr *eth_hdr =
					rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

				if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
					rte_pktmbuf_free(m);
					continue;
				}

				struct rte_ipv4_hdr *ip_hdr =
					reinterpret_cast<struct rte_ipv4_hdr *>(eth_hdr + 1);

				if (ip_hdr->next_proto_id != IPPROTO_UDP) {
					rte_pktmbuf_free(m);
					continue;
				}

				struct rte_udp_hdr *udp_hdr =
					reinterpret_cast<struct rte_udp_hdr *>(
						reinterpret_cast<unsigned char *>(ip_hdr) +
						(ip_hdr->version_ihl & 0x0F) * 4);

				if (udp_hdr->dst_port != listen_port) {
					rte_pktmbuf_free(m);
					continue;
				}

				struct alb_backend *backend = next_backend();
				rte_ether_addr_copy(&backend->mac, &eth_hdr->dst_addr);
				ip_hdr->dst_addr = backend->ip;
				udp_hdr->dst_port = backend->port;

				ip_hdr->hdr_checksum = 0;
				ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
				udp_hdr->dgram_cksum = 0;

				bufs[nb_to_tx++] = m;
			}

			if (nb_to_tx == 0)
				continue;

			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_to_tx);

			if (unlikely(nb_tx < nb_to_tx)) {
				for (uint16_t buf = nb_tx; buf < nb_to_tx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

int
main(int argc, char *argv[])
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
		rte_exit(EXIT_FAILURE, "Usage: alb <config.yaml> <listen_port>\n");

	const char *config_file = argv[1];
	listen_port = htons(static_cast<uint16_t>(atoi(argv[2])));

	if (listen_port == 0)
		rte_exit(EXIT_FAILURE, "Port must be non-zero\n");

	printf("Listening for UDP packets on port %s\n", argv[2]);

	if (alb_config_load(config_file, &config) < 0)
		rte_exit(EXIT_FAILURE, "Failed to load config: %s\n", config_file);

	alb_config_print(&config);

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	rr_index = 0;
	lcore_main();

	rte_eal_cleanup();

	return 0;
}
