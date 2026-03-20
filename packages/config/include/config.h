/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef ALB_CONFIG_H
#define ALB_CONFIG_H

#include <rte_ether.h>
#include <stdint.h>

#define ALB_MAX_BACKENDS 64

struct alb_backend {
	uint32_t ip;
	uint16_t port;
	struct rte_ether_addr mac;
};

struct alb_config {
	struct alb_backend backends[ALB_MAX_BACKENDS];
	uint16_t num_backends;
};

int alb_config_load(const char *filename, struct alb_config *config);
void alb_config_print(const struct alb_config *config);

#endif
