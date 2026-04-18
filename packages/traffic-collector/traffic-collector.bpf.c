/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

#define FILTER_RATE 1

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} counts SEC(".maps");

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

	__u32 key = ip->daddr;

	__u64 *val = bpf_map_lookup_elem(&counts, &key);

	if (val) {
		__sync_fetch_and_add(val, 1);
	} else {
		__u64 init = 1;
		bpf_map_update_elem(&counts, &key, &init, BPF_NOEXIST);
	}

	// bpf_printk("packet from %x to %x\n", ip->saddr, ip->daddr);

	return XDP_PASS;
}
