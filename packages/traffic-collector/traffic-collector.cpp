#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include "traffic-collector.skel.hpp"

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
	struct traffic_collector_bpf *skel;
	int err;
	int timeout_sec = 100;

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

	int ifindex = if_nametoindex("tailscale0");
	if (!ifindex) {
		fprintf(stderr, "Failed to find interface enp0s31f6\n");
		goto cleanup;
	}

	err = bpf_xdp_attach(
	    ifindex, bpf_program__fd(skel->progs.xdp_prog_simple), 0, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach XDP program: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat "
	       "/sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	for (int i = 0; i < timeout_sec && running; i++) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	if (ifindex)
		bpf_xdp_detach(ifindex, 0, NULL);
	traffic_collector_bpf__destroy(skel);
	return -err;
}
