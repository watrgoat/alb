# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

APP = alb
SRCS-y := main.c

PROJECT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
BUILD_DIR := $(PROJECT_ROOT)/build
CONFIG := $(PROJECT_ROOT)/config.yaml

PKGCONF ?= pkg-config

ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk) -DALLOW_EXPERIMENTAL_API
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lyaml
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lyaml

all: shared

.PHONY: shared static
shared: $(BUILD_DIR)/$(APP)
static: $(BUILD_DIR)/$(APP)-static

$(BUILD_DIR)/$(APP): $(SRCS-y) Makefile $(PC_FILE) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

$(BUILD_DIR)/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

$(BUILD_DIR):
	@mkdir -p $@

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: run
run: shared
	@echo "Run: sudo $(BUILD_DIR)/$(APP) -l 0 --vdev=net_null0 --vdev=net_null1 -- $(CONFIG)"

.PHONY: test
test: shared
	sudo $(PROJECT_ROOT)/test/run_test.sh
