.SILENT:

# ==============================
# lfw - Linux Firewall
# Test Makefile
# ==============================

CC      := gcc
cstd    := -std=c11
CFLAGS  := -Wall -Wextra -Werror
OPTIMISE:= -O2
INCLUDES:= -Iinclude
BUILD   := build
TESTBIN := $(BUILD)/lfw_tests
PCAPTEST:= $(BUILD)/lfw_pcap_test

# ==============================
# Source files
# ==============================

SRC_CORE := \
	src/lfw_rules.c \
	src/lfw_engine.c \
	src/lfw_packet_parse.c

SRC_TEST := \
	tests/test_main.c \
	tests/test_packet_parse.c \
	tests/test_rules.c \
	tests/test_engine.c

PCAP_SRC := \
	tools/lfw_pcap_test.c

# ==============================
# Targets
# ==============================

.PHONY: all tests pcap-test clean

all: tests

tests: $(TESTBIN)
	@echo "[lfw] tests built successfully"

$(TESTBIN): $(SRC_CORE) $(SRC_TEST) | $(BUILD)
	$(CC) $(cstd) $(CFLAGS) $(OPTIMISE) $(INCLUDES) \
		$(SRC_CORE) $(SRC_TEST) \
		-o $(TESTBIN)

$(BUILD):
	mkdir -p $(BUILD)
	@echo "[MKDIR] Created build directory"


pcap-test: $(PCAPTEST)
	@echo "[lfw] PCAP test utility built successfully"

$(PCAPTEST): $(PCAP_SRC) $(SRC_CORE) | $(BUILD)
	$(CC) $(CFLAGS) \
		$(PCAP_SRC) $(SRC_CORE) \
		-Iinclude -lpcap \
		-o $(PCAPTEST)


clean:
	rm -rf $(BUILD)/
	@echo "[lfw] Build directory cleaned"

