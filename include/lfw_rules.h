// SPDX-License-Identifier: GPL-3.0-only

#ifndef LFW_RULES_H
#define LFW_RULES_H

#include "lfw_types.h"
#include "lfw_packet.h"

// Rule action
typedef enum {
    LFW_ACTION_UNSPECIFIED = 0,
    LFW_ACTION_ACCEPT,
    LFW_ACTION_DROP
} lfw_action_t;

// Rule match fields
typedef struct {
    lfw_ip_t src_ip;
    lfw_ip_t src_mask;
    lfw_ip_t dst_ip;
    lfw_ip_t dst_mask;
    bool     match_src_ip;
    bool     match_dst_ip;

    lfw_proto_t protocol;

    lfw_port_range_t src_port;
    lfw_port_range_t dst_port;
    bool             match_src_port;
    bool             match_dst_port;

    uint8_t          ip_version; // 0: any, 4: IPv4, 6: IPv6

    char             src_fqdn[128];
    char             dst_fqdn[128];
    bool             has_src_fqdn;
    bool             has_dst_fqdn;
} lfw_rule_match_t;

// Firewall rule
typedef struct {
    lfw_rule_match_t match;
    lfw_action_t     action;
    lfw_u64          hit_count;
    lfw_u64          byte_count;
} lfw_rule_t;

// Match API
bool lfw_rule_match(const lfw_rule_t *rule, const lfw_packet_t *packet);

// FQDN API
lfw_status_t lfw_rules_expand_fqdn(const lfw_rule_t *raw_rules, lfw_u32 raw_count,
                                   lfw_rule_t **expanded_rules, lfw_u32 *expanded_count);

#endif
