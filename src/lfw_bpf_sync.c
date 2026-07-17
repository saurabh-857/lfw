// SPDX-License-Identifier: GPL-3.0-only

#include "lfw_bpf.h"
#include "lfw_bpf_shared.h"
#include "lfw_log.h"
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

struct subnet_entry {
    lfw_u32 ip;
    lfw_u32 mask;
    struct rule_mask r_mask;
};

struct subnet6_entry {
    struct in6_addr ip;
    struct in6_addr mask;
    struct rule_mask r_mask;
};

static inline int get_prefix_len(lfw_u32 mask)
{
    lfw_u32 host_mask = ntohl(mask);
    int len = 0;
    for (int b = 31; b >= 0; b--) {
        if ((host_mask >> b) & 1) len++;
        else break;
    }
    return len;
}

static inline int get_prefix_len6(const struct in6_addr *mask)
{
    int len = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t byte = mask->s6_addr[i];
        for (int b = 7; b >= 0; b--) {
            if ((byte >> b) & 1) len++;
            else break;
        }
    }
    return len;
}

static bool subnet_contains(lfw_u32 ip_a, lfw_u32 mask_a, lfw_u32 ip_b, lfw_u32 mask_b)
{
    int len_a = get_prefix_len(mask_a);
    int len_b = get_prefix_len(mask_b);
    
    if (len_a > len_b)
        return false;
        
    return (ip_b & mask_a) == ip_a;
}

static bool subnet6_contains(const struct in6_addr *ip_a, const struct in6_addr *mask_a,
                             const struct in6_addr *ip_b, const struct in6_addr *mask_b)
{
    int len_a = get_prefix_len6(mask_a);
    int len_b = get_prefix_len6(mask_b);
    
    if (len_a > len_b)
        return false;
        
    for (int i = 0; i < 16; i++) {
        if ((ip_b->s6_addr[i] & mask_a->s6_addr[i]) != (ip_a->s6_addr[i] & mask_a->s6_addr[i]))
            return false;
    }
    return true;
}

static void set_bit(struct rule_mask *mask, int bit_idx)
{
    int word = bit_idx / 64;
    int bit = bit_idx % 64;
    mask->bits[word] |= (1ULL << bit);
}

static void or_masks(struct rule_mask *dest, const struct rule_mask *src)
{
    for (int i = 0; i < 4; i++) {
        dest->bits[i] |= src->bits[i];
    }
}

lfw_status_t lfw_bpf_sync_rules_to_fd(const lfw_rule_t *rules, lfw_u32 rule_count, lfw_action_t default_action, lfw_loglevel_t log_level,
                                      int rules_fd, int config_fd, int src_trie_fd, int dst_trie_fd,
                                      int src_trie6_fd, int dst_trie6_fd)
{
    if (rules_fd < 0 || config_fd < 0 || src_trie_fd < 0 || dst_trie_fd < 0 ||
        src_trie6_fd < 0 || dst_trie6_fd < 0) {
        lfw_log_error("BPF maps not initialized");
        return LFW_ERR_GENERIC;
    }

    // 1. Update config map
    __u32 idx_def = 0;
    __u32 val_def = (default_action == LFW_ACTION_ACCEPT) ? 1 : 2;
    if (bpf_map_update_elem(config_fd, &idx_def, &val_def, BPF_ANY) != 0) {
        lfw_log_error("Failed to update config default action: %s", strerror(errno));
        return LFW_ERR_GENERIC;
    }

    __u32 idx_cnt = 1;
    __u32 val_cnt = rule_count > 256 ? 256 : rule_count;
    if (bpf_map_update_elem(config_fd, &idx_cnt, &val_cnt, BPF_ANY) != 0) {
        lfw_log_error("Failed to update config rule count: %s", strerror(errno));
        return LFW_ERR_GENERIC;
    }

    __u32 idx_log = 2;
    __u32 val_log = (__u32)log_level;
    if (bpf_map_update_elem(config_fd, &idx_log, &val_log, BPF_ANY) != 0) {
        lfw_log_error("Failed to update config log level: %s", strerror(errno));
        return LFW_ERR_GENERIC;
    }

    // 3. Populate rules details map
    for (__u32 i = 0; i < 256; i++) {
        struct bpf_rule b_rule = {};
        if (i < val_cnt) {
            const lfw_rule_t *rule = &rules[i];
            b_rule.ip_version = rule->match.ip_version;
            
            if (b_rule.ip_version == 4) {
                b_rule.src.v4.ip = rule->match.src_ip.v4.addr;
                b_rule.src.v4.mask = rule->match.src_mask.v4.addr;
                b_rule.dst.v4.ip = rule->match.dst_ip.v4.addr;
                b_rule.dst.v4.mask = rule->match.dst_mask.v4.addr;
            } else if (b_rule.ip_version == 6) {
                memcpy(b_rule.src.v6.ip.s6_addr, rule->match.src_ip.v6.addr, 16);
                memcpy(b_rule.src.v6.mask.s6_addr, rule->match.src_mask.v6.addr, 16);
                memcpy(b_rule.dst.v6.ip.s6_addr, rule->match.dst_ip.v6.addr, 16);
                memcpy(b_rule.dst.v6.mask.s6_addr, rule->match.dst_mask.v6.addr, 16);
            }
            
            b_rule.src_port_min = rule->match.match_src_port ? rule->match.src_port.min : 0;
            b_rule.src_port_max = rule->match.match_src_port ? rule->match.src_port.max : 65535;
            b_rule.dst_port_min = rule->match.match_dst_port ? rule->match.dst_port.min : 0;
            b_rule.dst_port_max = rule->match.match_dst_port ? rule->match.dst_port.max : 65535;

            b_rule.match_src_ip = rule->match.match_src_ip ? 1 : 0;
            b_rule.match_dst_ip = rule->match.match_dst_ip ? 1 : 0;
            b_rule.protocol = rule->match.protocol;
            b_rule.match_src_port = rule->match.match_src_port ? 1 : 0;
            b_rule.match_dst_port = rule->match.match_dst_port ? 1 : 0;
            b_rule.action = (rule->action == LFW_ACTION_ACCEPT) ? 1 : 2;
            b_rule.hit_count = 0;
            b_rule.byte_count = 0;
        }

        if (bpf_map_update_elem(rules_fd, &i, &b_rule, BPF_ANY) != 0) {
            lfw_log_error("Failed to write BPF rule #%u: %s", i + 1, strerror(errno));
            return LFW_ERR_GENERIC;
        }
    }

    // 4. Compile and sync Source subnets (IPv4)
    struct subnet_entry src_subnets[256];
    int src_subnet_count = 0;

    src_subnets[0].ip = 0;
    src_subnets[0].mask = 0;
    memset(&src_subnets[0].r_mask, 0, sizeof(struct rule_mask));
    src_subnet_count = 1;

    for (__u32 i = 0; i < val_cnt; i++) {
        const lfw_rule_t *rule = &rules[i];
        if (rule->match.ip_version == 6) continue;

        lfw_u32 ip = rule->match.match_src_ip ? rule->match.src_ip.v4.addr : 0;
        lfw_u32 mask = rule->match.match_src_ip ? rule->match.src_mask.v4.addr : 0;

        bool found = false;
        for (int j = 0; j < src_subnet_count; j++) {
            if (src_subnets[j].ip == ip && src_subnets[j].mask == mask) {
                found = true;
                break;
            }
        }

        if (!found && src_subnet_count < 256) {
            src_subnets[src_subnet_count].ip = ip;
            src_subnets[src_subnet_count].mask = mask;
            memset(&src_subnets[src_subnet_count].r_mask, 0, sizeof(struct rule_mask));
            src_subnet_count++;
        }
    }

    for (int j = 0; j < src_subnet_count; j++) {
        lfw_u32 ip = src_subnets[j].ip;
        lfw_u32 mask = src_subnets[j].mask;

        for (__u32 i = 0; i < val_cnt; i++) {
            const lfw_rule_t *rule = &rules[i];
            if (rule->match.ip_version == 6) continue;

            if (!rule->match.match_src_ip || (rule->match.src_ip.v4.addr == ip && rule->match.src_mask.v4.addr == mask)) {
                set_bit(&src_subnets[j].r_mask, i);
            }
        }
    }

    bool src_changed = true;
    while (src_changed) {
        src_changed = false;
        for (int j = 0; j < src_subnet_count; j++) {
            for (int k = 0; k < src_subnet_count; k++) {
                if (j == k) continue;
                if (subnet_contains(src_subnets[k].ip, src_subnets[k].mask, src_subnets[j].ip, src_subnets[j].mask)) {
                    struct rule_mask old_mask = src_subnets[j].r_mask;
                    or_masks(&src_subnets[j].r_mask, &src_subnets[k].r_mask);
                    if (memcmp(&old_mask, &src_subnets[j].r_mask, sizeof(struct rule_mask)) != 0) {
                        src_changed = true;
                    }
                }
            }
        }
    }

    for (int j = 0; j < src_subnet_count; j++) {
        struct lpm_key key = {
            .prefixlen = get_prefix_len(src_subnets[j].mask),
            .ip = src_subnets[j].ip
        };
        if (bpf_map_update_elem(src_trie_fd, &key, &src_subnets[j].r_mask, BPF_ANY) != 0) {
            lfw_log_error("Failed to write BPF src trie element: %s", strerror(errno));
            return LFW_ERR_GENERIC;
        }
    }

    // 5. Compile and sync Source subnets (IPv6)
    struct subnet6_entry src6_subnets[256];
    int src6_subnet_count = 0;

    memset(&src6_subnets[0].ip, 0, 16);
    memset(&src6_subnets[0].mask, 0, 16);
    memset(&src6_subnets[0].r_mask, 0, sizeof(struct rule_mask));
    src6_subnet_count = 1;

    for (__u32 i = 0; i < val_cnt; i++) {
        const lfw_rule_t *rule = &rules[i];
        if (rule->match.ip_version == 4) continue;

        struct in6_addr ip = {};
        struct in6_addr mask = {};
        if (rule->match.match_src_ip) {
            memcpy(&ip, rule->match.src_ip.v6.addr, 16);
            memcpy(&mask, rule->match.src_mask.v6.addr, 16);
        }

        bool found = false;
        for (int j = 0; j < src6_subnet_count; j++) {
            if (memcmp(src6_subnets[j].ip.s6_addr, ip.s6_addr, 16) == 0 &&
                memcmp(src6_subnets[j].mask.s6_addr, mask.s6_addr, 16) == 0) {
                found = true;
                break;
            }
        }

        if (!found && src6_subnet_count < 256) {
            src6_subnets[src6_subnet_count].ip = ip;
            src6_subnets[src6_subnet_count].mask = mask;
            memset(&src6_subnets[src6_subnet_count].r_mask, 0, sizeof(struct rule_mask));
            src6_subnet_count++;
        }
    }

    for (int j = 0; j < src6_subnet_count; j++) {
        struct in6_addr ip = src6_subnets[j].ip;
        struct in6_addr mask = src6_subnets[j].mask;

        for (__u32 i = 0; i < val_cnt; i++) {
            const lfw_rule_t *rule = &rules[i];
            if (rule->match.ip_version == 4) continue;

            if (!rule->match.match_src_ip ||
                (memcmp(rule->match.src_ip.v6.addr, ip.s6_addr, 16) == 0 &&
                 memcmp(rule->match.src_mask.v6.addr, mask.s6_addr, 16) == 0)) {
                set_bit(&src6_subnets[j].r_mask, i);
            }
        }
    }

    bool src6_changed = true;
    while (src6_changed) {
        src6_changed = false;
        for (int j = 0; j < src6_subnet_count; j++) {
            for (int k = 0; k < src6_subnet_count; k++) {
                if (j == k) continue;
                if (subnet6_contains(&src6_subnets[k].ip, &src6_subnets[k].mask,
                                     &src6_subnets[j].ip, &src6_subnets[j].mask)) {
                    struct rule_mask old_mask = src6_subnets[j].r_mask;
                    or_masks(&src6_subnets[j].r_mask, &src6_subnets[k].r_mask);
                    if (memcmp(&old_mask, &src6_subnets[j].r_mask, sizeof(struct rule_mask)) != 0) {
                        src6_changed = true;
                    }
                }
            }
        }
    }

    for (int j = 0; j < src6_subnet_count; j++) {
        struct lpm6_key key = {
            .prefixlen = get_prefix_len6(&src6_subnets[j].mask),
            .ip = src6_subnets[j].ip
        };
        if (bpf_map_update_elem(src_trie6_fd, &key, &src6_subnets[j].r_mask, BPF_ANY) != 0) {
            lfw_log_error("Failed to write BPF src IPv6 trie element: %s", strerror(errno));
            return LFW_ERR_GENERIC;
        }
    }

    // 6. Compile and sync Destination subnets (IPv4)
    struct subnet_entry dst_subnets[256];
    int dst_subnet_count = 0;

    dst_subnets[0].ip = 0;
    dst_subnets[0].mask = 0;
    memset(&dst_subnets[0].r_mask, 0, sizeof(struct rule_mask));
    dst_subnet_count = 1;

    for (__u32 i = 0; i < val_cnt; i++) {
        const lfw_rule_t *rule = &rules[i];
        if (rule->match.ip_version == 6) continue;

        lfw_u32 ip = rule->match.match_dst_ip ? rule->match.dst_ip.v4.addr : 0;
        lfw_u32 mask = rule->match.match_dst_ip ? rule->match.dst_mask.v4.addr : 0;

        bool found = false;
        for (int j = 0; j < dst_subnet_count; j++) {
            if (dst_subnets[j].ip == ip && dst_subnets[j].mask == mask) {
                found = true;
                break;
            }
        }

        if (!found && dst_subnet_count < 256) {
            dst_subnets[dst_subnet_count].ip = ip;
            dst_subnets[dst_subnet_count].mask = mask;
            memset(&dst_subnets[dst_subnet_count].r_mask, 0, sizeof(struct rule_mask));
            dst_subnet_count++;
        }
    }

    for (int j = 0; j < dst_subnet_count; j++) {
        lfw_u32 ip = dst_subnets[j].ip;
        lfw_u32 mask = dst_subnets[j].mask;

        for (__u32 i = 0; i < val_cnt; i++) {
            const lfw_rule_t *rule = &rules[i];
            if (rule->match.ip_version == 6) continue;

            if (!rule->match.match_dst_ip || (rule->match.dst_ip.v4.addr == ip && rule->match.dst_mask.v4.addr == mask)) {
                set_bit(&dst_subnets[j].r_mask, i);
            }
        }
    }

    bool dst_changed = true;
    while (dst_changed) {
        dst_changed = false;
        for (int j = 0; j < dst_subnet_count; j++) {
            for (int k = 0; k < dst_subnet_count; k++) {
                if (j == k) continue;
                if (subnet_contains(dst_subnets[k].ip, dst_subnets[k].mask, dst_subnets[j].ip, dst_subnets[j].mask)) {
                    struct rule_mask old_mask = dst_subnets[j].r_mask;
                    or_masks(&dst_subnets[j].r_mask, &dst_subnets[k].r_mask);
                    if (memcmp(&old_mask, &dst_subnets[j].r_mask, sizeof(struct rule_mask)) != 0) {
                        dst_changed = true;
                    }
                }
            }
        }
    }

    for (int j = 0; j < dst_subnet_count; j++) {
        struct lpm_key key = {
            .prefixlen = get_prefix_len(dst_subnets[j].mask),
            .ip = dst_subnets[j].ip
        };
        if (bpf_map_update_elem(dst_trie_fd, &key, &dst_subnets[j].r_mask, BPF_ANY) != 0) {
            lfw_log_error("Failed to write BPF dst trie element: %s", strerror(errno));
            return LFW_ERR_GENERIC;
        }
    }

    // 7. Compile and sync Destination subnets (IPv6)
    struct subnet6_entry dst6_subnets[256];
    int dst6_subnet_count = 0;

    memset(&dst6_subnets[0].ip, 0, 16);
    memset(&dst6_subnets[0].mask, 0, 16);
    memset(&dst6_subnets[0].r_mask, 0, sizeof(struct rule_mask));
    dst6_subnet_count = 1;

    for (__u32 i = 0; i < val_cnt; i++) {
        const lfw_rule_t *rule = &rules[i];
        if (rule->match.ip_version == 4) continue;

        struct in6_addr ip = {};
        struct in6_addr mask = {};
        if (rule->match.match_dst_ip) {
            memcpy(&ip, rule->match.dst_ip.v6.addr, 16);
            memcpy(&mask, rule->match.dst_mask.v6.addr, 16);
        }

        bool found = false;
        for (int j = 0; j < dst6_subnet_count; j++) {
            if (memcmp(dst6_subnets[j].ip.s6_addr, ip.s6_addr, 16) == 0 &&
                memcmp(dst6_subnets[j].mask.s6_addr, mask.s6_addr, 16) == 0) {
                found = true;
                break;
            }
        }

        if (!found && dst6_subnet_count < 256) {
            dst6_subnets[dst6_subnet_count].ip = ip;
            dst6_subnets[dst6_subnet_count].mask = mask;
            memset(&dst6_subnets[dst6_subnet_count].r_mask, 0, sizeof(struct rule_mask));
            dst6_subnet_count++;
        }
    }

    for (int j = 0; j < dst6_subnet_count; j++) {
        struct in6_addr ip = dst6_subnets[j].ip;
        struct in6_addr mask = dst6_subnets[j].mask;

        for (__u32 i = 0; i < val_cnt; i++) {
            const lfw_rule_t *rule = &rules[i];
            if (rule->match.ip_version == 4) continue;

            if (!rule->match.match_dst_ip ||
                (memcmp(rule->match.dst_ip.v6.addr, ip.s6_addr, 16) == 0 &&
                 memcmp(rule->match.dst_mask.v6.addr, mask.s6_addr, 16) == 0)) {
                set_bit(&dst6_subnets[j].r_mask, i);
            }
        }
    }

    bool dst6_changed = true;
    while (dst6_changed) {
        dst6_changed = false;
        for (int j = 0; j < dst6_subnet_count; j++) {
            for (int k = 0; k < dst6_subnet_count; k++) {
                if (j == k) continue;
                if (subnet6_contains(&dst6_subnets[k].ip, &dst6_subnets[k].mask,
                                     &dst6_subnets[j].ip, &dst6_subnets[j].mask)) {
                    struct rule_mask old_mask = dst6_subnets[j].r_mask;
                    or_masks(&dst6_subnets[j].r_mask, &dst6_subnets[k].r_mask);
                    if (memcmp(&old_mask, &dst6_subnets[j].r_mask, sizeof(struct rule_mask)) != 0) {
                        dst6_changed = true;
                    }
                }
            }
        }
    }

    for (int j = 0; j < dst6_subnet_count; j++) {
        struct lpm6_key key = {
            .prefixlen = get_prefix_len6(&dst6_subnets[j].mask),
            .ip = dst6_subnets[j].ip
        };
        if (bpf_map_update_elem(dst_trie6_fd, &key, &dst6_subnets[j].r_mask, BPF_ANY) != 0) {
            lfw_log_error("Failed to write BPF dst IPv6 trie element: %s", strerror(errno));
            return LFW_ERR_GENERIC;
        }
    }

    return LFW_OK;
}

static void format_rule(const struct bpf_rule *rule, char *buf, size_t buf_len)
{
    int offset = 0;
    offset += snprintf(buf + offset, buf_len - offset, "%s",
                       rule->action == 1 ? "allow" : "deny");

    const char *proto = "any";
    if (rule->protocol == LFW_PROTO_TCP) proto = "tcp";
    else if (rule->protocol == LFW_PROTO_UDP) proto = "udp";
    else if (rule->protocol == LFW_PROTO_ICMP) proto = "icmp";
    else if (rule->protocol == LFW_PROTO_IGMP) proto = "igmp";
    else if (rule->protocol == LFW_PROTO_ICMPV6) proto = "icmpv6";
    else if (rule->protocol == LFW_PROTO_ESP) proto = "esp";
    else if (rule->protocol == LFW_PROTO_AH) proto = "ah";

    if (rule->protocol != 0) {
        offset += snprintf(buf + offset, buf_len - offset, " %s", proto);
    }

    if (rule->match_dst_port) {
        if (rule->dst_port_min == rule->dst_port_max) {
            offset += snprintf(buf + offset, buf_len - offset, " %u", rule->dst_port_min);
        } else {
            offset += snprintf(buf + offset, buf_len - offset, " %u-%u", rule->dst_port_min, rule->dst_port_max);
        }
    }

    if (rule->match_src_ip) {
        char ip_str[64];
        if (rule->ip_version == 4) {
            struct in_addr in;
            in.s_addr = rule->src.v4.ip;
            inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
            int prefix = get_prefix_len(rule->src.v4.mask);
            if (prefix == 32) {
                offset += snprintf(buf + offset, buf_len - offset, " from %s", ip_str);
            } else {
                offset += snprintf(buf + offset, buf_len - offset, " from %s/%d", ip_str, prefix);
            }
        } else {
            struct in6_addr in6;
            memcpy(&in6, &rule->src.v6.ip, 16);
            inet_ntop(AF_INET6, &in6, ip_str, sizeof(ip_str));
            int prefix = get_prefix_len6(&rule->src.v6.mask);
            if (prefix == 128) {
                offset += snprintf(buf + offset, buf_len - offset, " from %s", ip_str);
            } else {
                offset += snprintf(buf + offset, buf_len - offset, " from %s/%d", ip_str, prefix);
            }
        }
    } else {
        offset += snprintf(buf + offset, buf_len - offset, " from any");
    }

    if (rule->match_dst_ip) {
        char ip_str[64];
        if (rule->ip_version == 4) {
            struct in_addr in;
            in.s_addr = rule->dst.v4.ip;
            inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
            int prefix = get_prefix_len(rule->dst.v4.mask);
            if (prefix == 32) {
                offset += snprintf(buf + offset, buf_len - offset, " to %s", ip_str);
            } else {
                offset += snprintf(buf + offset, buf_len - offset, " to %s/%d", ip_str, prefix);
            }
        } else {
            struct in6_addr in6;
            memcpy(&in6, &rule->dst.v6.ip, 16);
            inet_ntop(AF_INET6, &in6, ip_str, sizeof(ip_str));
            int prefix = get_prefix_len6(&rule->dst.v6.mask);
            if (prefix == 128) {
                offset += snprintf(buf + offset, buf_len - offset, " to %s", ip_str);
            } else {
                offset += snprintf(buf + offset, buf_len - offset, " to %s/%d", ip_str, prefix);
            }
        }
    } else {
        offset += snprintf(buf + offset, buf_len - offset, " to any");
    }
}

void lfw_bpf_dump_stats(const lfw_rule_t *orig_rules, lfw_u32 orig_rule_count, lfw_action_t default_action)
{
    (void)orig_rules;

    int conntrack_fd = lfw_bpf_get_conntrack_map_fd();
    int conntrack_v6_fd = lfw_bpf_get_conntrack_map_v6_fd();
    int rules_fd = lfw_bpf_get_rules_map_fd();
    int config_fd = lfw_bpf_get_config_map_fd();

    if (conntrack_fd < 0 || conntrack_v6_fd < 0 || rules_fd < 0 || config_fd < 0) {
        lfw_log_error("BPF maps not initialized for stats dump");
        return;
    }

    lfw_u32 conn_count = 0;
    struct conntrack_key key = {}, next_key = {};
    while (bpf_map_get_next_key(conntrack_fd, &key, &next_key) == 0) {
        conn_count++;
        key = next_key;
    }

    lfw_u32 conn6_count = 0;
    struct conntrack_key_v6 key6 = {}, next_key6 = {};
    while (bpf_map_get_next_key(conntrack_v6_fd, &key6, &next_key6) == 0) {
        conn6_count++;
        key6 = next_key6;
    }

    __u32 idx_cnt = 1;
    __u32 rule_count = 0;
    if (bpf_map_lookup_elem(config_fd, &idx_cnt, &rule_count) != 0) {
        rule_count = orig_rule_count;
    }

    lfw_log_info("=== eBPF/TC Firewall Statistics ===");
    lfw_log_info("Active IPv4 Connections Count: %u", conn_count);
    lfw_log_info("Active IPv6 Connections Count: %u", conn6_count);
    lfw_log_info("Default Policy Verdict: %s",
                 default_action == LFW_ACTION_ACCEPT ? "ACCEPT" : "DROP");
    lfw_log_info("Installed Rules Count: %u", rule_count);

    for (__u32 i = 0; i < rule_count && i < 256; i++) {
        struct bpf_rule b_rule = {};
        if (bpf_map_lookup_elem(rules_fd, &i, &b_rule) == 0) {
            char rule_str[256];
            format_rule(&b_rule, rule_str, sizeof(rule_str));
            lfw_log_info("  Rule #%u [%s]: hits=%lu, bytes=%lu",
                         i + 1, rule_str, (unsigned long)b_rule.hit_count, (unsigned long)b_rule.byte_count);
        }
    }

    // Dump LPM Tries
    int src_trie_fd = lfw_bpf_get_src_ip_trie_fd();
    int dst_trie_fd = lfw_bpf_get_dst_ip_trie_fd();
    int src_trie6_fd = lfw_bpf_get_src_ip6_trie_fd();
    int dst_trie6_fd = lfw_bpf_get_dst_ip6_trie_fd();

    if (src_trie_fd >= 0) {
        lfw_log_info("=== src_ip_trie ===");
        struct lpm_key k = {}, nk = {};
        struct rule_mask m = {};
        int r = bpf_map_get_next_key(src_trie_fd, NULL, &nk);
        while (r == 0) {
            k = nk;
            if (bpf_map_lookup_elem(src_trie_fd, &k, &m) == 0) {
                char ip_str[64];
                struct in_addr in = {.s_addr = k.ip};
                inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
                lfw_log_info("  prefixlen=%u, ip=%s -> mask bits: %llu %llu", k.prefixlen, ip_str, m.bits[0], m.bits[1]);
            }
            r = bpf_map_get_next_key(src_trie_fd, &k, &nk);
        }
    }

    if (dst_trie_fd >= 0) {
        lfw_log_info("=== dst_ip_trie ===");
        struct lpm_key k = {}, nk = {};
        struct rule_mask m = {};
        int r = bpf_map_get_next_key(dst_trie_fd, NULL, &nk);
        while (r == 0) {
            k = nk;
            if (bpf_map_lookup_elem(dst_trie_fd, &k, &m) == 0) {
                char ip_str[64];
                struct in_addr in = {.s_addr = k.ip};
                inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
                lfw_log_info("  prefixlen=%u, ip=%s -> mask bits: %llu %llu", k.prefixlen, ip_str, m.bits[0], m.bits[1]);
            }
            r = bpf_map_get_next_key(dst_trie_fd, &k, &nk);
        }
    }

    if (src_trie6_fd >= 0) {
        lfw_log_info("=== src_ip6_trie ===");
        struct lpm6_key k = {}, nk = {};
        struct rule_mask m = {};
        int r = bpf_map_get_next_key(src_trie6_fd, NULL, &nk);
        while (r == 0) {
            k = nk;
            if (bpf_map_lookup_elem(src_trie6_fd, &k, &m) == 0) {
                char ip_str[64];
                inet_ntop(AF_INET6, &k.ip, ip_str, sizeof(ip_str));
                lfw_log_info("  prefixlen=%u, ip=%s -> mask bits: %llu %llu", k.prefixlen, ip_str, m.bits[0], m.bits[1]);
            }
            r = bpf_map_get_next_key(src_trie6_fd, &k, &nk);
        }
    }

    if (dst_trie6_fd >= 0) {
        lfw_log_info("=== dst_ip6_trie ===");
        struct lpm6_key k = {}, nk = {};
        struct rule_mask m = {};
        int r = bpf_map_get_next_key(dst_trie6_fd, NULL, &nk);
        while (r == 0) {
            k = nk;
            if (bpf_map_lookup_elem(dst_trie6_fd, &k, &m) == 0) {
                char ip_str[64];
                inet_ntop(AF_INET6, &k.ip, ip_str, sizeof(ip_str));
                lfw_log_info("  prefixlen=%u, ip=%s -> mask bits: %llu %llu", k.prefixlen, ip_str, m.bits[0], m.bits[1]);
            }
            r = bpf_map_get_next_key(dst_trie6_fd, &k, &nk);
        }
    }

    lfw_log_info("===========================");
}

lfw_status_t lfw_bpf_sync_rules(const lfw_rule_t *rules, lfw_u32 rule_count, lfw_action_t default_action, lfw_loglevel_t log_level)
{
    int rules_fd = lfw_bpf_get_rules_map_fd();
    int config_fd = lfw_bpf_get_config_map_fd();
    int src_trie_fd = lfw_bpf_get_src_ip_trie_fd();
    int dst_trie_fd = lfw_bpf_get_dst_ip_trie_fd();
    int src_trie6_fd = lfw_bpf_get_src_ip6_trie_fd();
    int dst_trie6_fd = lfw_bpf_get_dst_ip6_trie_fd();

    return lfw_bpf_sync_rules_to_fd(rules, rule_count, default_action, log_level,
                                    rules_fd, config_fd, src_trie_fd, dst_trie_fd,
                                    src_trie6_fd, dst_trie6_fd);
}
