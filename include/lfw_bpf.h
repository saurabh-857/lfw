// SPDX-License-Identifier: GPL-3.0-only

#ifndef LFW_BPF_H
#define LFW_BPF_H

#include "lfw_types.h"
#include "lfw_rules.h"

// Initialize BPF subsystem, load program, and attach to interface TC hooks
lfw_status_t lfw_bpf_init(const char *ifname, const char *bpf_obj_path);

// Synchronize user-space rules to BPF maps
lfw_status_t lfw_bpf_sync_rules(const lfw_rule_t *rules, lfw_u32 rule_count, lfw_action_t default_action, lfw_loglevel_t log_level);

// Synchronize user-space rules to specific BPF map FDs
lfw_status_t lfw_bpf_sync_rules_to_fd(const lfw_rule_t *rules, lfw_u32 rule_count, lfw_action_t default_action, lfw_loglevel_t log_level,
                                      int rules_fd, int config_fd, int src_trie_fd, int dst_trie_fd,
                                      int src_trie6_fd, int dst_trie6_fd);

// Reload rules by loading a new BPF instance and atomically replacing active filters
lfw_status_t lfw_bpf_reload(const char *ifname, const char *bpf_obj_path,
                            const lfw_rule_t *new_rules, lfw_u32 new_rule_count,
                            lfw_action_t new_default_action, lfw_loglevel_t log_level);

// Detach BPF filters and cleanup resources
void lfw_bpf_cleanup(void);

// Read statistics from BPF maps and dump to syslog
void lfw_bpf_dump_stats(const lfw_rule_t *orig_rules, lfw_u32 orig_rule_count, lfw_action_t default_action);

// Map file descriptor getters
int lfw_bpf_get_conntrack_map_fd(void);
int lfw_bpf_get_rules_map_fd(void);
int lfw_bpf_get_config_map_fd(void);
int lfw_bpf_get_src_ip_trie_fd(void);
int lfw_bpf_get_dst_ip_trie_fd(void);
int lfw_bpf_get_src_ip6_trie_fd(void);
int lfw_bpf_get_dst_ip6_trie_fd(void);
int lfw_bpf_get_conntrack_map_v6_fd(void);
int lfw_bpf_get_events_ringbuf_fd(void);

#endif
