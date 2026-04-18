#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "traffic-collector.skel.hpp"

#define MAX_ENTRIES	    1024
#define SAMPLE_INTERVAL_SEC 5

static volatile bool running = true;

void sig_handler(int sig)
{
	running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: traffic-collector [interface]");
		return 1;
	}
	struct traffic_collector_bpf *skel;
	int err;
	int ifindex = 0;
	int map_fd = 0;
	FILE *csv = NULL;
	__u32 prev_keys[MAX_ENTRIES];
	__u64 prev_vals[MAX_ENTRIES];
	int prev_count = 0;
	memset(prev_keys, 0, sizeof(prev_keys));
	memset(prev_vals, 0, sizeof(prev_vals));

	libbpf_set_print(libbpf_print_fn);

	skel = traffic_collector_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = traffic_collector_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Failed to find interface tailscale0\n");
		goto cleanup;
	}

	err = bpf_xdp_attach(
	    ifindex, bpf_program__fd(skel->progs.xdp_prog_simple), 0, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach XDP program: %d\n", err);
		goto cleanup;
	}

	csv = fopen("traffic-stats.csv", "w");
	if (!csv) {
		fprintf(stderr, "Failed to open traffic-stats.csv\n");
		goto cleanup;
	}
	fprintf(csv, "timestamp,ip,packets_delta\n");

	printf("Collecting traffic stats to traffic-stats.csv every %ds...\n",
	       SAMPLE_INTERVAL_SEC);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	map_fd = bpf_map__fd(skel->maps.counts);

	while (running) {
		sleep(SAMPLE_INTERVAL_SEC);
		if (!running)
			break;

		time_t now = time(NULL);
		__u32 cur_keys[MAX_ENTRIES];
		__u64 cur_vals[MAX_ENTRIES];
		int cur_count = 0;

		__u32 key = 0, next_key = 0;
		while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0 &&
		       cur_count < MAX_ENTRIES) {
			__u64 value = 0;
			bpf_map_lookup_elem(map_fd, &next_key, &value);
			cur_keys[cur_count] = next_key;
			cur_vals[cur_count] = value;
			cur_count++;
			key = next_key;
		}

		for (int i = 0; i < cur_count; i++) {
			__u64 prev = 0;
			for (int j = 0; j < prev_count; j++) {
				if (prev_keys[j] == cur_keys[i]) {
					prev = prev_vals[j];
					break;
				}
			}
			__u64 delta = cur_vals[i] - prev;
			if (delta == 0)
				continue;

			char ip_str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &cur_keys[i], ip_str,
				  sizeof(ip_str));
			fprintf(csv, "%ld,%s,%llu\n", now, ip_str,
				(unsigned long long)delta);
		}
		fflush(csv);

		memcpy(prev_keys, cur_keys, cur_count * sizeof(__u32));
		memcpy(prev_vals, cur_vals, cur_count * sizeof(__u64));
		prev_count = cur_count;
	}

cleanup:
	if (csv)
		fclose(csv);
	if (ifindex)
		bpf_xdp_detach(ifindex, 0, NULL);
	traffic_collector_bpf__destroy(skel);
	return -err;
}
