// SPDX-License-Identifier: GPL-3.0-only

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h> // IWYU pragma: keep
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lfw_bpf.h"
#include "lfw_bpf_shared.h"
#include "lfw_config.h"
#include "lfw_log.h"
#include "lfw_rules.h"

// Timeouts in nanoseconds (matching kernel BPF)
#define TCP_TIMEOUT_SYN_SENT_NS (20ULL * 1000000000ULL)
#define TCP_TIMEOUT_SYN_RECV_NS (20ULL * 1000000000ULL)
#define TCP_TIMEOUT_FIN_WAIT_NS (30ULL * 1000000000ULL)
#define TCP_TIMEOUT_ESTABLISHED_NS (300ULL * 1000000000ULL)
#define TCP_TIMEOUT_CLOSED_NS (10ULL * 1000000000ULL)
#define UDP_TIMEOUT_NS (60ULL * 1000000000ULL)

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload_requested = 0;
static volatile sig_atomic_t g_dump_requested = 0;

static lfw_rule_t *g_rules = NULL;
static lfw_u32 g_rule_count = 0;
static lfw_action_t g_default_action = LFW_ACTION_DROP;
static char g_config_path[256] = "/etc/lfw/lfw.rules";

static pthread_t g_gc_thread;
static bool g_gc_running = false;

static pthread_t g_telemetry_thread;
static bool g_telemetry_running = false;

static volatile int64_t g_clock_offset = 0;
static volatile bool g_clock_offset_initialized = false;

static int handle_event(void *ctx, void *data, size_t data_sz) {
  (void)ctx;
  if (data_sz < sizeof(struct lfw_event))
    return 0;

  // Telemetry rate limiting (max 100 log messages per second to avoid syslog bottleneck)
  static __u64 last_log_time = 0;
  static __u32 log_count_this_sec = 0;
  struct timespec ts;
  if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0) {
    __u64 now = (__u64)ts.tv_sec;
    if (now != last_log_time) {
      last_log_time = now;
      log_count_this_sec = 0;
    }
    if (log_count_this_sec >= 100) {
      return 0; // Skip logging to prevent CPU starvation
    }
    log_count_this_sec++;
  }

  struct lfw_event *event = (struct lfw_event *)data;

  // Calibrate clock offset between userspace CLOCK_MONOTONIC and kernel bpf_ktime_get_ns()
  struct timespec offset_ts;
  if (clock_gettime(CLOCK_MONOTONIC, &offset_ts) == 0) {
    int64_t userspace_now = (int64_t)offset_ts.tv_sec * 1000000000LL + offset_ts.tv_nsec;
    g_clock_offset = userspace_now - (int64_t)event->timestamp;
    g_clock_offset_initialized = true;
  }

  char src_ip_str[64];
  char dst_ip_str[64];

  if (event->ip_version == 4) {
    struct in_addr src_in = {.s_addr = event->src_ip.v4};
    struct in_addr dst_in = {.s_addr = event->dst_ip.v4};
    inet_ntop(AF_INET, &src_in, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &dst_in, dst_ip_str, sizeof(dst_ip_str));
  } else {
    struct in6_addr src_in6;
    struct in6_addr dst_in6;
    memcpy(&src_in6, &event->src_ip.v6, 16);
    memcpy(&dst_in6, &event->dst_ip.v6, 16);
    inet_ntop(AF_INET6, &src_in6, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET6, &dst_in6, dst_ip_str, sizeof(dst_ip_str));
  }

  char proto_buf[16];
  const char *proto = proto_buf;
  if (event->proto == 6)
    proto = "tcp";
  else if (event->proto == 17)
    proto = "udp";
  else if (event->proto == 1)
    proto = "icmp";
  else if (event->proto == 2)
    proto = "igmp";
  else if (event->proto == 58)
    proto = "icmpv6";
  else if (event->proto == 50)
    proto = "esp";
  else if (event->proto == 51)
    proto = "ah";
  else
    snprintf(proto_buf, sizeof(proto_buf), "%u", event->proto);

  const char *action = (event->action == 1) ? "ALLOW" : "DROP";

  // Print telemetry log line as structured JSON
  lfw_log_info("{\"timestamp\": %llu, \"action\": \"%s\", \"proto\": \"%s\", "
               "\"src\": \"%s:%u\", \"dst\": \"%s:%u\", \"len\": %llu}",
               (unsigned long long)event->timestamp, action, proto, src_ip_str,
               ntohs(event->src_port), dst_ip_str, ntohs(event->dst_port),
               (unsigned long long)event->pkt_len);

  return 0;
}

static void *telemetry_loop(void *arg) {
  (void)arg;
  int ringbuf_fd = lfw_bpf_get_events_ringbuf_fd();
  if (ringbuf_fd < 0) {
    lfw_log_error("Failed to get Ring Buffer FD");
    return NULL;
  }

  struct ring_buffer *rb =
      ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
  if (!rb) {
    lfw_log_error("Failed to initialize ring buffer");
    return NULL;
  }

  while (g_running) {
    int err = ring_buffer__poll(rb, 100);
    if (err < 0 && err != -EINTR) {
      lfw_log_error("Error polling ring buffer: %d", err);
      break;
    }
  }

  ring_buffer__free(rb);
  return NULL;
}

static void handle_signal(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    g_running = 0;
  } else if (sig == SIGHUP) {
    g_reload_requested = 1;
  } else if (sig == SIGUSR1) {
    g_dump_requested = 1;
  }
}

static void *conntrack_gc_loop(void *arg) {
  (void)arg;
  while (g_running) {
    for (int i = 0; i < 10 && g_running; i++) {
      sleep(1);
    }
    if (!g_running)
      break;

    if (!g_clock_offset_initialized) {
      continue; // Wait until telemetry calibrates the clock offset
    }
    int64_t offset = g_clock_offset;

    struct timespec ts;
    __u64 now_u = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
      now_u = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    } else {
      continue;
    }

    int64_t adjusted_now = (int64_t)now_u - offset;

    // IPv4 GC
    int fd = lfw_bpf_get_conntrack_map_fd();
    if (fd >= 0) {
      struct conntrack_key *delete_keys = NULL;
      size_t delete_count = 0;
      size_t delete_cap = 0;

      struct conntrack_key key = {}, next_key = {};
      struct conntrack_val val = {};
      int has_more = bpf_map_get_next_key(fd, NULL, &next_key) == 0;
      while (has_more) {
        key = next_key;
        has_more = bpf_map_get_next_key(fd, &key, &next_key) == 0;

        if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
          __u64 timeout = UDP_TIMEOUT_NS;
          if (key.proto == IPPROTO_TCP) { // TCP
            if (val.state == LFW_TCP_STATE_SYN_SENT)
              timeout = TCP_TIMEOUT_SYN_SENT_NS;
            else if (val.state == LFW_TCP_STATE_SYN_RECV)
              timeout = TCP_TIMEOUT_SYN_RECV_NS;
            else if (val.state == LFW_TCP_STATE_FIN_WAIT)
              timeout = TCP_TIMEOUT_FIN_WAIT_NS;
            else if (val.state == LFW_TCP_STATE_CLOSED)
              timeout = TCP_TIMEOUT_CLOSED_NS;
            else
              timeout = TCP_TIMEOUT_ESTABLISHED_NS;
          }
          if (adjusted_now > (int64_t)val.last_seen && adjusted_now - (int64_t)val.last_seen > (int64_t)timeout) {
            if (delete_count >= delete_cap) {
              size_t new_cap = delete_cap == 0 ? 256 : delete_cap * 2;
              struct conntrack_key *tmp = realloc(delete_keys, new_cap * sizeof(struct conntrack_key));
              if (tmp) {
                delete_keys = tmp;
                delete_cap = new_cap;
              } else {
                break;
              }
            }
            delete_keys[delete_count++] = key;
          }
        }
      }

      for (size_t i = 0; i < delete_count; i++) {
        bpf_map_delete_elem(fd, &delete_keys[i]);
      }
      free(delete_keys);
    }

    // IPv6 GC
    int fd_v6 = lfw_bpf_get_conntrack_map_v6_fd();
    if (fd_v6 >= 0) {
      struct conntrack_key_v6 *delete_keys_v6 = NULL;
      size_t delete_count_v6 = 0;
      size_t delete_cap_v6 = 0;

      struct conntrack_key_v6 key = {}, next_key = {};
      struct conntrack_val val = {};
      int has_more = bpf_map_get_next_key(fd_v6, NULL, &next_key) == 0;
      while (has_more) {
        key = next_key;
        has_more = bpf_map_get_next_key(fd_v6, &key, &next_key) == 0;

        if (bpf_map_lookup_elem(fd_v6, &key, &val) == 0) {
          __u64 timeout = UDP_TIMEOUT_NS;
          if (key.proto == IPPROTO_TCP) { // TCP
            if (val.state == LFW_TCP_STATE_SYN_SENT)
              timeout = TCP_TIMEOUT_SYN_SENT_NS;
            else if (val.state == LFW_TCP_STATE_SYN_RECV)
              timeout = TCP_TIMEOUT_SYN_RECV_NS;
            else if (val.state == LFW_TCP_STATE_FIN_WAIT)
              timeout = TCP_TIMEOUT_FIN_WAIT_NS;
            else if (val.state == LFW_TCP_STATE_CLOSED)
              timeout = TCP_TIMEOUT_CLOSED_NS;
            else
              timeout = TCP_TIMEOUT_ESTABLISHED_NS;
          }
          if (adjusted_now > (int64_t)val.last_seen && adjusted_now - (int64_t)val.last_seen > (int64_t)timeout) {
            if (delete_count_v6 >= delete_cap_v6) {
              size_t new_cap = delete_cap_v6 == 0 ? 256 : delete_cap_v6 * 2;
              struct conntrack_key_v6 *tmp = realloc(delete_keys_v6, new_cap * sizeof(struct conntrack_key_v6));
              if (tmp) {
                delete_keys_v6 = tmp;
                delete_cap_v6 = new_cap;
              } else {
                break;
              }
            }
            delete_keys_v6[delete_count_v6++] = key;
          }
        }
      }

      for (size_t i = 0; i < delete_count_v6; i++) {
        bpf_map_delete_elem(fd_v6, &delete_keys_v6[i]);
      }
      free(delete_keys_v6);
    }
  }
  return NULL;
}

static void cleanup(void) {
  lfw_log_info("cleaning up BPF subsystem...");
  g_running = 0;

  if (g_telemetry_running) {
    pthread_join(g_telemetry_thread, NULL);
    g_telemetry_running = false;
  }

  if (g_gc_running) {
    pthread_join(g_gc_thread, NULL);
    g_gc_running = false;
  }

  lfw_bpf_cleanup();

  if (g_rules) {
    lfw_config_free_rules(g_rules);
    g_rules = NULL;
  }
  lfw_log_close();
}

int main(int argc, char **argv) {
  // Root privilege check
  if (geteuid() != 0) {
    fprintf(stderr, "[lfw] run as root\n");
    return 1;
  }

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <interface> [rules_file_path]\n", argv[0]);
    return 1;
  }

  const char *ifname = argv[1];
  if (argc > 2) {
    strncpy(g_config_path, argv[2], sizeof(g_config_path) - 1);
  }

  lfw_log_init(LFW_LOG_SYSLOG);

  // Register signal handlers
  struct sigaction sa = {};
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGUSR1, &sa, NULL);

  atexit(cleanup);

  // 1. Load config rules
  lfw_status_t st = lfw_config_load_file(g_config_path, &g_default_action,
                                         &g_rules, &g_rule_count);

  if (st != LFW_OK) {
    lfw_log_error("failed to load config: %s", g_config_path);
    return 1;
  }

  // 2. Initialize BPF subsystem
  const char *bpf_obj_path = "build/lfw_bpf.o";
  if (access(bpf_obj_path, F_OK) != 0) {
    bpf_obj_path = "/usr/local/share/lfw/lfw_bpf.o";
  }
  st = lfw_bpf_init(ifname, bpf_obj_path);
  if (st != LFW_OK) {
    lfw_log_error("failed to initialize BPF on interface %s", ifname);
    return 1;
  }

  // Spawn telemetry thread
  if (pthread_create(&g_telemetry_thread, NULL, telemetry_loop, NULL) == 0) {
    g_telemetry_running = true;
  } else {
    lfw_log_error("failed to spawn telemetry thread");
    return 1;
  }

  // 3. Sync initial rules to BPF maps
  st = lfw_bpf_sync_rules(g_rules, g_rule_count, g_default_action);
  if (st != LFW_OK) {
    lfw_log_error("failed to sync rules to BPF maps");
    return 1;
  }

  // 4. Spawn connection tracking garbage collector thread
  if (pthread_create(&g_gc_thread, NULL, conntrack_gc_loop, NULL) == 0) {
    g_gc_running = true;
  } else {
    lfw_log_error("failed to spawn conntrack GC thread");
    return 1;
  }

  lfw_log_info("daemon starting on interface %s", ifname);
  lfw_log_info("config: %s, rules: %u, default: %s", g_config_path,
               g_rule_count,
               g_default_action == LFW_ACTION_ACCEPT ? "ACCEPT" : "DROP");

  // Main event loop
  while (g_running) {
    if (g_reload_requested) {
      g_reload_requested = 0;
      lfw_rule_t *new_rules = NULL;
      lfw_u32 new_rule_count = 0;
      lfw_action_t new_default_action = LFW_ACTION_DROP;

      lfw_status_t reload_st = lfw_config_load_file(
          g_config_path, &new_default_action, &new_rules, &new_rule_count);

      if (reload_st == LFW_OK) {
        // Atomic BPF reload and replacement
        if (lfw_bpf_reload(ifname, bpf_obj_path, new_rules, new_rule_count, new_default_action) ==
            LFW_OK) {
          lfw_config_free_rules(g_rules);
          g_rules = new_rules;
          g_rule_count = new_rule_count;
          g_default_action = new_default_action;
          lfw_log_info("Rules configuration reloaded successfully");
        } else {
          lfw_config_free_rules(new_rules);
          lfw_log_error("Failed to reload and sync new rules to BPF");
        }
      } else {
        lfw_log_error("Failed to reload rules configuration file: %s",
                      g_config_path);
      }
    }

    if (g_dump_requested) {
      g_dump_requested = 0;
      lfw_bpf_dump_stats(g_rules, g_rule_count, g_default_action);
    }

    pause();
  }

  lfw_log_info("shutdown complete");

  return 0;
}
