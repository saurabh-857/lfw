#include "lfw_rules.h"

// Match IPv4
static inline bool match_ip(const lfw_ipv4_t *rule_ip,
                            const lfw_ipv4_t *pkt_ip,
                            bool enabled)
{
    if (!enabled)
        return true;

    return rule_ip->addr == pkt_ip->addr;
}

// Match port
static inline bool match_port(const lfw_port_t *rule_port,
                            const lfw_port_t *pkt_port,
                            bool enabled)
{
    if (!enabled)
        return true;

    return rule_port->port == pkt_port->port;
}

// Match protocol
static inline bool match_proto(lfw_proto_t rule_proto,
                                lfw_proto_t pkt_proto)
{
    if (rule_proto == LFW_PROTO_ANY)
        return true;

    return rule_proto == pkt_proto;
}

bool lfw_rule_match(const lfw_rule_t *rule,
                    const lfw_packet_t *packet)
{
    if (!rule || !packet)
        return false;

    // Protocol check first
    if (!match_proto(rule->match.protocol,
                    packet->protocol))
        return false;

    // IP match
    if (!match_ip(&rule->match.src_ip,
                &packet->ip4.src,
                rule->match.match_src_ip))
        return false;

    if (!match_ip(&rule->match.dst_ip,
                &packet->ip4.dst,
                rule->match.match_dst_ip))
        return false;

    // Ports only relevant for TCP/UDP
    if (packet->protocol == LFW_PROTO_TCP ||
        packet->protocol == LFW_PROTO_UDP)
    {
        if (!match_port(&rule->match.src_port,
                        &packet->l4.src_port,
                        rule->match.match_src_port))
            return false;

        if (!match_port(&rule->match.dst_port,
                        &packet->l4.dst_port,
                        rule->match.match_dst_port))
            return false;
    }

    return true;
}
