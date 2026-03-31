/* SPDX-License-Identifier: BSD-3-Clause */
#include "config.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_temp_config(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	assert(f != NULL);
	fputs(content, f);
	fclose(f);
}

static void test_basic_config(void)
{
	const char *yaml = "backends:\n"
			   "  - ip: 10.0.0.1\n"
			   "    port: 8080\n"
			   "    mac: aa:bb:cc:dd:ee:ff\n"
			   "  - ip: 10.0.0.2\n"
			   "    port: 9090\n"
			   "    mac: 11:22:33:44:55:66\n"
			   "    weight: 5\n";

	const char *path = "/tmp/alb_test_config.yaml";
	write_temp_config(path, yaml);

	struct alb_config config;
	int ret = alb_config_load(path, &config);
	assert(ret == 0);
	assert(config.num_backends == 2);

	struct in_addr expected_ip1, expected_ip2;
	inet_aton("10.0.0.1", &expected_ip1);
	inet_aton("10.0.0.2", &expected_ip2);

	assert(config.backends[0].ip == expected_ip1.s_addr);
	assert(config.backends[0].port == htons(8080));
	assert(config.backends[0].weight == 1);

	assert(config.backends[1].ip == expected_ip2.s_addr);
	assert(config.backends[1].port == htons(9090));
	assert(config.backends[1].weight == 5);

	assert(config.backends[0].mac.addr_bytes[0] == 0xaa);
	assert(config.backends[1].mac.addr_bytes[5] == 0x66);

	unlink(path);
	printf("test_basic_config: PASSED\n");
}

static void test_missing_file(void)
{
	struct alb_config config;
	int ret = alb_config_load("/nonexistent/path.yaml", &config);
	assert(ret == -1);
	printf("test_missing_file: PASSED\n");
}

static void test_empty_backends(void)
{
	const char *yaml = "backends:\n";
	const char *path = "/tmp/alb_test_empty.yaml";
	write_temp_config(path, yaml);

	struct alb_config config;
	int ret = alb_config_load(path, &config);
	assert(ret == -1);

	unlink(path);
	printf("test_empty_backends: PASSED\n");
}

static void test_weight_zero_defaults_to_one(void)
{
	const char *yaml = "backends:\n"
			   "  - ip: 10.0.0.1\n"
			   "    port: 80\n"
			   "    mac: 00:00:00:00:00:01\n"
			   "    weight: 0\n";

	const char *path = "/tmp/alb_test_weight.yaml";
	write_temp_config(path, yaml);

	struct alb_config config;
	int ret = alb_config_load(path, &config);
	assert(ret == 0);
	assert(config.backends[0].weight == 1);

	unlink(path);
	printf("test_weight_zero_defaults_to_one: PASSED\n");
}

int main(void)
{
	test_basic_config();
	test_missing_file();
	test_empty_backends();
	test_weight_zero_defaults_to_one();

	printf("\nAll config tests passed!\n");
	return 0;
}
