/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <yaml.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

struct backend_server {
	uint32_t ip;
	uint16_t port;
	struct rte_ether_addr mac;
};

static struct backend_server backend;

static int
parse_mac(const char *str, struct rte_ether_addr *addr)
{
	unsigned int bytes[6];
	if (sscanf(str, "%x:%x:%x:%x:%x:%x",
		   &bytes[0], &bytes[1], &bytes[2],
		   &bytes[3], &bytes[4], &bytes[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++)
		addr->addr_bytes[i] = (uint8_t)bytes[i];
	return 0;
}

static int
load_config(const char *filename)
{
	FILE *file = fopen(filename, "r");
	if (!file) {
		printf("Failed to open config file: %s\n", filename);
		return -1;
	}

	yaml_parser_t parser;
	yaml_event_t event;

	if (!yaml_parser_initialize(&parser)) {
		fclose(file);
		return -1;
	}

	yaml_parser_set_input_file(&parser, file);

	char current_key[64] = {0};
	int in_backends = 0;
	int in_backend_item = 0;
	int expect_value = 0;

	while (1) {
		if (!yaml_parser_parse(&parser, &event))
			break;

		if (event.type == YAML_STREAM_END_EVENT) {
			yaml_event_delete(&event);
			break;
		}

		if (event.type == YAML_SCALAR_EVENT) {
			const char *value = (const char *)event.data.scalar.value;

			if (strcmp(value, "backends") == 0) {
				in_backends = 1;
			} else if (in_backends && in_backend_item) {
				if (expect_value) {
					if (strcmp(current_key, "ip") == 0) {
						struct in_addr addr;
						if (inet_aton(value, &addr))
							backend.ip = addr.s_addr;
					} else if (strcmp(current_key, "port") == 0) {
						backend.port = htons((uint16_t)atoi(value));
					} else if (strcmp(current_key, "mac") == 0) {
						parse_mac(value, &backend.mac);
					}
					expect_value = 0;
				} else {
					strncpy(current_key, value, sizeof(current_key) - 1);
					current_key[sizeof(current_key) - 1] = '\0';
					expect_value = 1;
				}
			}
		} else if (event.type == YAML_MAPPING_START_EVENT && in_backends) {
			in_backend_item = 1;
		} else if (event.type == YAML_MAPPING_END_EVENT && in_backend_item) {
			break;
		}

		yaml_event_delete(&event);
	}

	yaml_parser_delete(&parser);
	fclose(file);

	printf("Loaded backend: IP=%u.%u.%u.%u port=%u MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       (backend.ip) & 0xFF, (backend.ip >> 8) & 0xFF,
	       (backend.ip >> 16) & 0xFF, (backend.ip >> 24) & 0xFF,
	       ntohs(backend.port),
	       backend.mac.addr_bytes[0], backend.mac.addr_bytes[1],
	       backend.mac.addr_bytes[2], backend.mac.addr_bytes[3],
	       backend.mac.addr_bytes[4], backend.mac.addr_bytes[5]);

	return 0;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
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

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

 /* Basic forwarding application lcore. 8< */
static __rte_noreturn void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Main work of application loop. 8< */
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
					(struct rte_ipv4_hdr *)(eth_hdr + 1);

				if (ip_hdr->next_proto_id != IPPROTO_UDP) {
					rte_pktmbuf_free(m);
					continue;
				}

				struct rte_udp_hdr *udp_hdr =
					(struct rte_udp_hdr *)((unsigned char *)ip_hdr +
						(ip_hdr->version_ihl & 0x0F) * 4);

				rte_ether_addr_copy(&backend.mac, &eth_hdr->dst_addr);
				ip_hdr->dst_addr = backend.ip;
				udp_hdr->dst_port = backend.port;

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
	/* >8 End of loop. */
}
/* >8 End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	const char *config_file;
	if (argc > 1)
		config_file = argv[1];
	else
		rte_exit(EXIT_FAILURE, "Missing config file\n");

	if (load_config(config_file) < 0)
		rte_exit(EXIT_FAILURE, "Failed to load config: %s\n", config_file);


	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. 8< */
	lcore_main();
	/* >8 End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
