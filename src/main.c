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

static lfw_rule_t *g_raw_rules = NULL;
static lfw_u32 g_raw_rule_count = 0;
static lfw_rule_t *g_rules = NULL;
static lfw_u32 g_rule_count = 0;
static lfw_action_t g_default_action = LFW_ACTION_DROP;
static char g_config_path[256] = "/etc/lfw/lfw.rules";
static char g_ifname[32] = {0};

static bool g_cli_loglevel_override = false;
static lfw_loglevel_t g_cli_loglevel = LFW_LOG_OPTIMAL;

static pthread_t g_gc_thread;
static bool g_gc_running = false;

static pthread_t g_fqdn_thread;
static bool g_fqdn_running = false;

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

    lfw_log_debug("GC loop: Starting connection tracking sweep...");

    lfw_bpf_lock();

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
      lfw_log_debug("GC loop (v4): Swept %zu expired connections", delete_count);
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
      lfw_log_debug("GC loop (v6): Swept %zu expired connections", delete_count_v6);
      free(delete_keys_v6);
    }

    lfw_bpf_unlock();
  }
  return NULL;
}

static void *fqdn_resolver_loop(void *arg) {
  (void)arg;
  const char *bpf_obj_path = "build/lfw_bpf.o";
  if (access(bpf_obj_path, F_OK) != 0) {
    bpf_obj_path = "/usr/local/share/lfw/lfw_bpf.o";
  }

  while (g_running) {
    for (int i = 0; i < 60 && g_running; i++) {
      sleep(1);
    }
    if (!g_running)
      break;

    lfw_bpf_lock();
    if (!g_raw_rules || g_raw_rule_count == 0) {
      lfw_bpf_unlock();
      continue;
    }

    lfw_rule_t *new_concrete_rules = NULL;
    lfw_u32 new_concrete_count = 0;
    lfw_status_t st = lfw_rules_expand_fqdn(g_raw_rules, g_raw_rule_count, &new_concrete_rules, &new_concrete_count);
    if (st != LFW_OK) {
      lfw_bpf_unlock();
      continue;
    }

    bool changed = false;
    if (new_concrete_count != g_rule_count) {
      changed = true;
    } else {
      for (lfw_u32 i = 0; i < g_rule_count; i++) {
        if (memcmp(&g_rules[i].match, &new_concrete_rules[i].match, sizeof(lfw_rule_match_t)) != 0 ||
            g_rules[i].action != new_concrete_rules[i].action) {
          changed = true;
          break;
        }
      }
    }

    if (changed) {
      lfw_log_info("FQDN resolved IPs changed, reloading BPF maps...");
      lfw_loglevel_t active_loglevel = g_cli_loglevel_override ? g_cli_loglevel : LFW_LOG_OPTIMAL;
      if (lfw_bpf_reload(g_ifname, bpf_obj_path, new_concrete_rules, new_concrete_count, g_default_action, active_loglevel) == LFW_OK) {
        lfw_config_free_rules(g_rules);
        g_rules = new_concrete_rules;
        g_rule_count = new_concrete_count;
        lfw_log_info("FQDN rules atomically reloaded");
      } else {
        lfw_config_free_rules(new_concrete_rules);
        lfw_log_error("Failed to reload BPF maps with updated FQDN IPs");
      }
    } else {
      lfw_config_free_rules(new_concrete_rules);
    }
    lfw_bpf_unlock();
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

  if (g_fqdn_running) {
    pthread_join(g_fqdn_thread, NULL);
    g_fqdn_running = false;
  }

  lfw_bpf_lock();
  lfw_bpf_cleanup();
  lfw_bpf_unlock();

  if (g_rules) {
    lfw_config_free_rules(g_rules);
    g_rules = NULL;
  }
  if (g_raw_rules) {
    lfw_config_free_rules(g_raw_rules);
    g_raw_rules = NULL;
  }
  lfw_log_close();
}

int main(int argc, char **argv) {
  // Root privilege check
  if (geteuid() != 0) {
    fprintf(stderr, "[lfw] run as root\n");
    return 1;
  }

  const char *ifname = NULL;
  const char *rules_path = NULL;
  const char *cli_loglevel_str = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--log-level") == 0) {
      if (i + 1 < argc) {
        cli_loglevel_str = argv[i + 1];
        i++;
      } else {
        fprintf(stderr, "Error: --log-level requires an argument\n");
        return 1;
      }
    } else if (strncmp(argv[i], "--log-level=", 12) == 0) {
      cli_loglevel_str = argv[i] + 12;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      return 1;
    } else {
      if (!ifname) {
        ifname = argv[i];
      } else if (!rules_path) {
        rules_path = argv[i];
      } else {
        fprintf(stderr, "Too many arguments: %s\n", argv[i]);
        return 1;
      }
    }
  }

  if (!ifname) {
    fprintf(stderr, "Usage: %s <interface> [rules_file_path] [--log-level minimal|optimal|max|super_max]\n", argv[0]);
    return 1;
  }

  if (rules_path) {
    strncpy(g_config_path, rules_path, sizeof(g_config_path) - 1);
  }

  if (cli_loglevel_str) {
    lfw_loglevel_t cli_level = LFW_LOG_OPTIMAL;
    if (strcasecmp(cli_loglevel_str, "minimal") == 0) {
      cli_level = LFW_LOG_MINIMAL;
    } else if (strcasecmp(cli_loglevel_str, "optimal") == 0) {
      cli_level = LFW_LOG_OPTIMAL;
    } else if (strcasecmp(cli_loglevel_str, "max") == 0) {
      cli_level = LFW_LOG_MAX;
    } else if (strcasecmp(cli_loglevel_str, "super_max") == 0) {
      cli_level = LFW_LOG_SUPER_MAX;
    } else {
      fprintf(stderr, "Invalid log level: %s (choose minimal, optimal, max, super_max)\n", cli_loglevel_str);
      return 1;
    }
    g_cli_loglevel_override = true;
    g_cli_loglevel = cli_level;
  }

  lfw_log_init(LFW_LOG_SYSLOG);
  if (g_cli_loglevel_override) {
    lfw_log_set_level(g_cli_loglevel);
  }

  // Register signal handlers
  struct sigaction sa = {};
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGUSR1, &sa, NULL);

  atexit(cleanup);

  if (ifname) {
    strncpy(g_ifname, ifname, sizeof(g_ifname) - 1);
  }

  // 1. Load config rules
  lfw_loglevel_t file_loglevel = LFW_LOG_OPTIMAL;
  lfw_status_t st = lfw_config_load_file(g_config_path, &g_default_action,
                                         &g_raw_rules, &g_raw_rule_count, &file_loglevel);

  if (st != LFW_OK) {
    lfw_log_error("failed to load config: %s", g_config_path);
    return 1;
  }

  // Expand FQDN rules
  st = lfw_rules_expand_fqdn(g_raw_rules, g_raw_rule_count, &g_rules, &g_rule_count);
  if (st != LFW_OK) {
    lfw_log_error("failed to expand FQDN rules");
    return 1;
  }

  if (!g_cli_loglevel_override) {
    lfw_log_set_level(file_loglevel);
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
  st = lfw_bpf_sync_rules(g_rules, g_rule_count, g_default_action, lfw_log_get_level());
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

  // Spawn FQDN re-resolution thread
  if (pthread_create(&g_fqdn_thread, NULL, fqdn_resolver_loop, NULL) == 0) {
    g_fqdn_running = true;
  } else {
    lfw_log_error("failed to spawn FQDN resolver thread");
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
      lfw_loglevel_t new_loglevel = LFW_LOG_OPTIMAL;

      lfw_status_t reload_st = lfw_config_load_file(
          g_config_path, &new_default_action, &new_rules, &new_rule_count, &new_loglevel);

      if (reload_st == LFW_OK) {
        lfw_bpf_lock();
        lfw_rule_t *expanded_rules = NULL;
        lfw_u32 expanded_count = 0;
        lfw_status_t exp_status = lfw_rules_expand_fqdn(new_rules, new_rule_count, &expanded_rules, &expanded_count);
        if (exp_status == LFW_OK) {
          lfw_loglevel_t active_loglevel = g_cli_loglevel_override ? g_cli_loglevel : new_loglevel;
          if (lfw_bpf_reload(g_ifname, bpf_obj_path, expanded_rules, expanded_count, new_default_action, active_loglevel) == LFW_OK) {
            lfw_config_free_rules(g_raw_rules);
            g_raw_rules = new_rules;
            g_raw_rule_count = new_rule_count;

            lfw_config_free_rules(g_rules);
            g_rules = expanded_rules;
            g_rule_count = expanded_count;

            g_default_action = new_default_action;
            if (!g_cli_loglevel_override) {
              lfw_log_set_level(new_loglevel);
            }
            lfw_log_info("Rules configuration reloaded successfully");
          } else {
            lfw_config_free_rules(expanded_rules);
            lfw_config_free_rules(new_rules);
            lfw_log_error("Failed to reload and sync new rules to BPF");
          }
        } else {
          lfw_config_free_rules(new_rules);
          lfw_log_error("Failed to expand FQDN rules during reload");
        }
        lfw_bpf_unlock();
      } else {
        lfw_log_error("Failed to reload rules configuration file: %s",
                      g_config_path);
      }
    }

    if (g_dump_requested) {
      g_dump_requested = 0;
      lfw_bpf_lock();
      lfw_bpf_dump_stats(g_rules, g_rule_count, g_default_action);
      lfw_bpf_unlock();
    }

    pause();
  }

  lfw_log_info("shutdown complete");

  return 0;
}
