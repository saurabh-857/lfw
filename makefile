.SILENT:

# ==============================
# lfw - Linux Firewall
# Test Makefile
# ==============================

CC      := gcc
cstd    := -std=c11
CFLAGS  := -Wall -Wextra -Werror -D_GNU_SOURCE
OPTIMISE:= -O2
INCLUDES:= -Iinclude
BUILD   := build
PCAPTEST:= $(BUILD)/lfw_pcap_test
LFWBIN  := $(BUILD)/lfw
TESTBIN := $(BUILD)/test_lfw

# ==============================
# Source files
# ==============================

SRC_CORE := \
	src/lfw_rules.c \
	src/lfw_engine.c \
	src/lfw_packet_parse.c \
	src/lfw_config.c \
	src/lfw_state.c \
	src/lfw_log.c

SRC_DAEMON := \
	src/main.c \
	src/lfw_bpf_loader.c \
	src/lfw_bpf_sync.c \
	$(SRC_CORE)

PCAP_SRC := \
	tools/lfw_pcap_test.c

BPF_OBJ := $(BUILD)/lfw_bpf.o

# ==============================
# Targets
# ==============================

.PHONY: all pcap-test lfw bpf clean test

all: lfw bpf

$(BUILD):
	mkdir -p $(BUILD)
	@echo "[MKDIR] Created build directory"


pcap-test: $(PCAPTEST)
	@echo "[lfw] PCAP test utility built successfully"

$(PCAPTEST): $(PCAP_SRC) $(SRC_CORE) | $(BUILD)
	$(CC) $(CFLAGS) \
		$(PCAP_SRC) $(SRC_CORE) \
		-Iinclude -lpcap -lpthread \
		-o $(PCAPTEST)

lfw: $(LFWBIN)
	@echo "[lfw] eBPF/TC firewall daemon built successfully"

bpf: $(BPF_OBJ)
	@echo "[lfw] eBPF kernel program built successfully"

$(BPF_OBJ): src/lfw_bpf.c | $(BUILD)
	clang -target bpf -mcpu=v3 -O2 -g $(INCLUDES) -I/usr/include/x86_64-linux-gnu \
		-c src/lfw_bpf.c -o $(BPF_OBJ)

$(LFWBIN): $(SRC_DAEMON) | $(BUILD)
	$(CC) $(cstd) $(CFLAGS) $(OPTIMISE) $(INCLUDES) \
		$(SRC_DAEMON) \
		-lbpf -lpthread \
		-o $(LFWBIN)


clean:
	rm -rf $(BUILD)/
	@echo "[lfw] Build directory cleaned"

test: $(TESTBIN)
	@echo "[lfw] Unit tests built successfully"
	./$(TESTBIN)

$(TESTBIN): scratch/test_lfw.c $(SRC_CORE) | $(BUILD)
	$(CC) $(cstd) $(CFLAGS) $(INCLUDES) \
		scratch/test_lfw.c $(SRC_CORE) \
		-lpthread \
		-o $(TESTBIN)

install: lfw bpf
	mkdir -p /usr/local/share/lfw
	mkdir -p /etc/lfw
	mkdir -p /etc/lfw/interfaces.enabled
	cp $(LFWBIN) /usr/local/bin/lfw
	cp $(BPF_OBJ) /usr/local/share/lfw/lfw_bpf.o
	if [ ! -f /etc/lfw/lfw.rules ]; then cp lfw.rules /etc/lfw/lfw.rules; fi
	cp lfw@.service /etc/systemd/system/lfw@.service
	systemctl daemon-reload
	rm -f /etc/lfw/interfaces.enabled/*

	# Automatically enable firewall for active network interfaces and loopback
	for dev in /sys/class/net/*; do \
		if [ -d "$$dev/device" ] || [ "$$(basename "$$dev")" = "lo" ]; then \
			iface=$$(basename "$$dev"); \
			if [ -f "$$dev/carrier" ] && [ "$$(cat "$$dev/carrier" 2>/dev/null)" = "1" ]; then \
				touch /etc/lfw/interfaces.enabled/$$iface; \
				echo "[lfw] Automatically enabled firewall on active interface: $$iface"; \
				systemctl enable "lfw@$$iface"; \
				systemctl restart "lfw@$$iface"; \
			else \
				systemctl disable "lfw@$$iface" >/dev/null 2>&1 || true; \
				systemctl stop "lfw@$$iface" >/dev/null 2>&1 || true; \
			fi; \
		fi; \
	done
	@echo "[lfw] Installed system-wide successfully!"


