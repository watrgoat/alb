/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define FILTER_RATE 1

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;
unsigned int count = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_DROP;

	count++;

	if (count % FILTER_RATE == 0) {
		bpf_printk("packet from %x to %x\n", ip->saddr, ip->daddr);
	}

	return XDP_PASS;
}
