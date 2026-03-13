/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <yaml.h>

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

int
alb_config_load(const char *filename, struct alb_config *config)
{
	FILE *file = fopen(filename, "r");
	if (!file) {
		printf("Failed to open config file: %s\n", filename);
		return -1;
	}

	memset(config, 0, sizeof(*config));

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
	struct alb_backend *current_backend = NULL;

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
			} else if (in_backends && in_backend_item && current_backend) {
				if (expect_value) {
					if (strcmp(current_key, "ip") == 0) {
						struct in_addr addr;
						if (inet_aton(value, &addr))
							current_backend->ip = addr.s_addr;
					} else if (strcmp(current_key, "port") == 0) {
						current_backend->port = htons((uint16_t)atoi(value));
					} else if (strcmp(current_key, "mac") == 0) {
						parse_mac(value, &current_backend->mac);
					}
					expect_value = 0;
				} else {
					strncpy(current_key, value, sizeof(current_key) - 1);
					current_key[sizeof(current_key) - 1] = '\0';
					expect_value = 1;
				}
			}
		} else if (event.type == YAML_MAPPING_START_EVENT && in_backends) {
			if (config->num_backends < ALB_MAX_BACKENDS) {
				current_backend = &config->backends[config->num_backends];
				in_backend_item = 1;
			}
		} else if (event.type == YAML_MAPPING_END_EVENT && in_backend_item) {
			config->num_backends++;
			current_backend = NULL;
			in_backend_item = 0;
		}

		yaml_event_delete(&event);
	}

	yaml_parser_delete(&parser);
	fclose(file);

	return config->num_backends > 0 ? 0 : -1;
}

void
alb_config_print(const struct alb_config *config)
{
	printf("Loaded %u backend(s):\n", config->num_backends);
	for (uint16_t i = 0; i < config->num_backends; i++) {
		const struct alb_backend *b = &config->backends[i];
		printf("  [%u] IP=%u.%u.%u.%u port=%u MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       i,
		       (b->ip) & 0xFF, (b->ip >> 8) & 0xFF,
		       (b->ip >> 16) & 0xFF, (b->ip >> 24) & 0xFF,
		       ntohs(b->port),
		       b->mac.addr_bytes[0], b->mac.addr_bytes[1],
		       b->mac.addr_bytes[2], b->mac.addr_bytes[3],
		       b->mac.addr_bytes[4], b->mac.addr_bytes[5]);
	}
}
