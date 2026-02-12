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
PCAPTEST:= $(BUILD)/lfw_pcap_test
LFWBIN  := $(BUILD)/lfw

# ==============================
# Source files
# ==============================

SRC_CORE := \
	src/lfw_rules.c \
	src/lfw_engine.c \
	src/lfw_packet_parse.c \
	src/lfw_config.c

SRC_DAEMON := \
	src/main.c \
	src/lfw_nfqueue.c \
	$(SRC_CORE)

PCAP_SRC := \
	tools/lfw_pcap_test.c

# ==============================
# Targets
# ==============================

.PHONY: all pcap-test lfw clean

all: lfw

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

lfw: $(LFWBIN)
	@echo "[lfw] NFQUEUE firewall daemon built successfully"

$(LFWBIN): $(SRC_DAEMON) | $(BUILD)
	$(CC) $(cstd) $(CFLAGS) $(OPTIMISE) $(INCLUDES) \
		$(SRC_DAEMON) \
		-lnetfilter_queue \
		-o $(LFWBIN)


clean:
	rm -rf $(BUILD)/
	@echo "[lfw] Build directory cleaned"

