#ifndef LFW_RULES_H
#define LFW_RULES_H

/*
 * lfw - Linux Firewall
 * Rule definitions
 */

#include "lfw_types.h"
#include "lfw_packet.h"

/* ==============================
 * Rule action
 * ============================== */
typedef enum {
    LFW_ACTION_UNSPECIFIED = 0,
    LFW_ACTION_ACCEPT,
    LFW_ACTION_DROP
} lfw_action_t;

/* ==============================
 * Rule match fields
 * ============================== */
typedef struct {
    /* Layer 3 */
    lfw_ipv4_t src_ip;
    lfw_ipv4_t dst_ip;
    bool       match_src_ip;
    bool       match_dst_ip;

    /* Layer 4 */
    lfw_proto_t protocol;
    lfw_port_t  src_port;
    lfw_port_t  dst_port;
    bool        match_src_port;
    bool        match_dst_port;

} lfw_rule_match_t;

/* ==============================
 * Firewall rule
 * ============================== */
typedef struct {
    lfw_rule_match_t match;
    lfw_action_t     action;
} lfw_rule_t;

/* ==============================
 * Rule evaluation API
 * ============================== */

/*
 * Evaluate a packet against a rule.
 * Returns true if rule matches packet.
 */
bool lfw_rule_match(const lfw_rule_t *rule, const lfw_packet_t *packet);

#endif /* LFW_RULES_H */
