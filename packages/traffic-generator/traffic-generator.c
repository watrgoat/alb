/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS	8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE	64

#define DST_ADDR RTE_IPV4(192, 168, 1, 1)
#define SRC_ADDR RTE_IPV4(192, 168, 1, 2)
#define DST_PORT 5678
#define SRC_PORT 1234

#define PAYLOAD_SIZE 32

static volatile uint64_t tx_counts[RTE_MAX_LCORE];
static const char *csv_path;
static volatile int running = 1;

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

struct lcore_args {
	struct rte_mempool *mbuf_pool;
	uint16_t port;
	uint16_t queue;
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool,
			    uint16_t nb_queues)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1;
	const uint16_t tx_rings = nb_queues; // main core for stats
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
						rte_eth_dev_socket_id(port),
						NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(
		    port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
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

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	       " %02" PRIx8 " %02" PRIx8 "\n",
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
static int lcore_tx(void *arg)
{

	uint16_t p;
	struct rte_mbuf *bufs[BURST_SIZE];

	struct lcore_args *args = arg;
	struct rte_mempool *mbuf_pool = args->mbuf_pool;
	uint16_t port = args->port;
	uint16_t queue = args->queue;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(p)
	if (rte_eth_dev_socket_id(p) >= 0 &&
	    rte_eth_dev_socket_id(p) != (int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
		       "polling thread.\n\tPerformance will "
		       "not be optimal.\n",
		       p);

	if (rte_pktmbuf_alloc_bulk(mbuf_pool, bufs, BURST_SIZE) != 0)
		rte_exit(EXIT_FAILURE, "Failed to allocate packet buffers\n");

	// Each pre-built packet gets a distinct UDP src_port so the ALB's RSS
	// hash spreads this TX worker's bursts across all RX queues. Without
	// this, every packet shares one 5-tuple and RSS collapses all traffic
	// to a single ALB worker (capping throughput at ~1 Mpps).
	// Offset by queue * BURST_SIZE so workers don't overlap each other's
	// port range — gives BURST_SIZE * nb_tx_workers distinct tuples total.
	uint16_t src_port_base = SRC_PORT + queue * BURST_SIZE;

	for (int i = 0; i < BURST_SIZE; i++) {
		struct rte_mbuf *pkt = bufs[i];

		uint16_t payload_len = PAYLOAD_SIZE;

		char *data = rte_pktmbuf_append(
		    pkt, sizeof(struct rte_ether_hdr) +
			     sizeof(struct rte_ipv4_hdr) +
			     sizeof(struct rte_udp_hdr) + payload_len);

		struct rte_ether_hdr *eth = (struct rte_ether_hdr *)data;
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
		struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);

		memset(&eth->dst_addr, 0xff, RTE_ETHER_ADDR_LEN);
		rte_eth_macaddr_get(port, &eth->src_addr);
		eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

		ip->version_ihl = 0x45;
		ip->total_length =
		    rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
				     sizeof(struct rte_udp_hdr) + payload_len);
		ip->time_to_live = 64;
		ip->next_proto_id = IPPROTO_UDP;
		ip->src_addr = rte_cpu_to_be_32(SRC_ADDR);
		ip->dst_addr = rte_cpu_to_be_32(DST_ADDR);
		ip->hdr_checksum = rte_ipv4_cksum(ip);

		udp->src_port = rte_cpu_to_be_16(src_port_base + i);
		udp->dst_port = rte_cpu_to_be_16(DST_PORT);
		udp->dgram_len =
		    rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + payload_len);

		// Pin refcount so the NIC's TX-complete path never frees our
		// pre-built packets. Lets the hot loop skip atomic refcount
		// updates per burst.
		rte_mbuf_refcnt_set(pkt, UINT16_MAX);
	}

	printf("\nCore %u transmitting packets. [Ctrl+C to quit]\n",
	       rte_lcore_id());

	/* Main work of application loop. 8< */
	while (running) {
		uint16_t nb_tx =
		    rte_eth_tx_burst(port, queue, bufs, BURST_SIZE);
		tx_counts[rte_lcore_id()] += nb_tx;
	}
	/* >8 End of loop. */

	// refcount was pinned to UINT16_MAX; drop it back so free() actually
	// returns the mbufs to the pool.
	for (int i = 0; i < BURST_SIZE; i++) {
		rte_mbuf_refcnt_set(bufs[i], 1);
		rte_pktmbuf_free(bufs[i]);
	}

	return 0;
}

static int lcore_rx(void *arg)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t port = 0;

	while (running) {
		uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
		for (int i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(bufs[i]);
	}
	return 0;
}
/* >8 End Basic forwarding application lcore. */

static void lcore_main(void)
{
	uint64_t last = 0;
	FILE *csv = NULL;

	if (csv_path) {
		csv = fopen(csv_path, "w");
		if (!csv) {
			fprintf(stderr, "Failed to open %s for TX CSV\n",
				csv_path);
		} else {
			fprintf(csv, "timestamp,pps_tx\n");
			fflush(csv);
		}
	}

	while (running) {
		rte_delay_us_sleep(1000000); // 1 second
		if (!running)
			break;

		uint64_t current = 0;
		unsigned id;
		RTE_LCORE_FOREACH_WORKER(id)
		current += tx_counts[id];

		uint64_t pps = current - last;
		last = current;
		printf("TX: %" PRIu64 " pps  (%.2f Mpps)\n", pps, pps / 1e6);

		if (csv) {
			fprintf(csv, "%ld,%" PRIu64 "\n", (long)time(NULL),
				pps);
			fflush(csv);
		}
	}

	if (csv)
		fclose(csv);
}
/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	uint16_t lcore_id;

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	uint16_t nb_tx_lcores = rte_lcore_count() - 2;

	// Unbuffered stdout so log output survives SIGINT.
	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	argc -= ret;
	argv += ret;

	// Optional first post-EAL arg: CSV path for per-second TX pps
	if (argc >= 2) {
		csv_path = argv[1];
		printf("TX stats CSV: %s\n", csv_path);
	}

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports <= 0)
		rte_exit(EXIT_FAILURE,
			 "Error: must have at least 1 compatible port\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create(
	    "MBUF_POOL", NUM_MBUFS * rte_lcore_count(), MBUF_CACHE_SIZE, 0,
	    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
	if (port_init(portid, mbuf_pool, nb_tx_lcores) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
			 portid);
	/* >8 End of initializing all ports. */

	// tx
	struct lcore_args args[RTE_MAX_LCORE];

	unsigned lcores[RTE_MAX_LCORE];
	int nb_lcores = 0;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	lcores[nb_lcores++] = lcore_id;

	// last worker does rx, rest do tx
	for (int i = 0; i < nb_lcores - 1; i++) {
		args[i].mbuf_pool = mbuf_pool;
		args[i].port = 0;
		args[i].queue = i;
		rte_eal_remote_launch(lcore_tx, &args[i], lcores[i]);
	}

	// rx drain
	rte_eal_remote_launch(lcore_rx, NULL, lcores[nb_lcores - 1]);

	// main core - stats (returns when SIGINT/SIGTERM flips `running`)
	lcore_main();

	// wait for workers to observe !running and return
	rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
