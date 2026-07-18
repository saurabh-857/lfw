// SPDX-License-Identifier: GPL-3.0-only

#include "lfw_rules.h"
#include <arpa/inet.h>

// Match IPv4
static inline bool match_ip4(const lfw_ipv4_t *rule_ip,
                             const lfw_ipv4_t *rule_mask,
                             const lfw_ipv4_t *pkt_ip,
                             bool enabled)
{
    if (!enabled)
        return true;

    return (pkt_ip->addr & rule_mask->addr) == (rule_ip->addr & rule_mask->addr);
}

// Match IPv6
static inline bool match_ip6(const lfw_ipv6_t *rule_ip,
                             const lfw_ipv6_t *rule_mask,
                             const lfw_ipv6_t *pkt_ip,
                             bool enabled)
{
    if (!enabled)
        return true;

    for (int i = 0; i < 16; i++) {
        if ((pkt_ip->addr[i] & rule_mask->addr[i]) != (rule_ip->addr[i] & rule_mask->addr[i]))
            return false;
    }
    return true;
}

// Match IP (wrapper)
static inline bool match_ip(const lfw_ip_t *rule_ip,
                            const lfw_ip_t *rule_mask,
                            const lfw_ip_t *pkt_ip,
                            bool enabled)
{
    if (!enabled)
        return true;

    if (pkt_ip->ip_version == 4) {
        return match_ip4(&rule_ip->v4, &rule_mask->v4, &pkt_ip->v4, enabled);
    } else if (pkt_ip->ip_version == 6) {
        return match_ip6(&rule_ip->v6, &rule_mask->v6, &pkt_ip->v6, enabled);
    }
    return false;
}

// Match port
static inline bool match_port(const lfw_port_range_t *rule_port,
                            const lfw_port_t *pkt_port,
                            bool enabled)
{
    if (!enabled)
        return true;

    lfw_u16 port = ntohs(pkt_port->port);
    return port >= rule_port->min && port <= rule_port->max;
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

    // Check version compatibility first
    if (rule->match.ip_version != 0 && rule->match.ip_version != packet->ip.src.ip_version)
        return false;

    // Protocol check
    if (!match_proto(rule->match.protocol,
                    packet->protocol))
        return false;

    // IP match
    if (!match_ip(&rule->match.src_ip,
                &rule->match.src_mask,
                &packet->ip.src,
                rule->match.match_src_ip))
        return false;

    if (!match_ip(&rule->match.dst_ip,
                &rule->match.dst_mask,
                &packet->ip.dst,
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct resolved_ip {
    lfw_ip_t ip;
    lfw_ip_t mask;
};

static int resolve_domain(const char *fqdn, struct resolved_ip **out_ips)
{
    struct addrinfo hints, *res = NULL, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(fqdn, NULL, &hints, &res);
    if (status != 0) {
        return 0;
    }

    int count = 0;
    for (p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET || p->ai_family == AF_INET6) {
            count++;
        }
    }

    if (count == 0) {
        freeaddrinfo(res);
        return 0;
    }

    struct resolved_ip *ips = malloc(count * sizeof(struct resolved_ip));
    if (!ips) {
        freeaddrinfo(res);
        return 0;
    }

    int idx = 0;
    for (p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            ips[idx].ip.ip_version = 4;
            ips[idx].ip.v4.addr = ipv4->sin_addr.s_addr;
            ips[idx].mask.ip_version = 4;
            ips[idx].mask.v4.addr = 0xFFFFFFFFu;
            idx++;
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            ips[idx].ip.ip_version = 6;
            memcpy(ips[idx].ip.v6.addr, ipv6->sin6_addr.s6_addr, 16);
            ips[idx].mask.ip_version = 6;
            memset(ips[idx].mask.v6.addr, 0xFF, 16);
            idx++;
        }
    }

    freeaddrinfo(res);
    *out_ips = ips;
    return count;
}

lfw_status_t lfw_rules_expand_fqdn(const lfw_rule_t *raw_rules, lfw_u32 raw_count,
                                   lfw_rule_t **expanded_rules, lfw_u32 *expanded_count)
{
    lfw_u32 cap = raw_count > 0 ? raw_count * 2 : 16;
    lfw_rule_t *list = malloc(cap * sizeof(lfw_rule_t));
    if (!list) return LFW_ERR_NO_MEMORY;

    lfw_u32 count = 0;

    for (lfw_u32 i = 0; i < raw_count; i++) {
        const lfw_rule_t *raw = &raw_rules[i];

        struct resolved_ip *src_ips = NULL;
        int src_count = 0;
        if (raw->match.has_src_fqdn) {
            src_count = resolve_domain(raw->match.src_fqdn, &src_ips);
            if (src_count == 0) {
                fprintf(stderr, "[lfw] Warning: failed to resolve FQDN '%s'\n", raw->match.src_fqdn);
                continue;
            }
        }

        struct resolved_ip *dst_ips = NULL;
        int dst_count = 0;
        if (raw->match.has_dst_fqdn) {
            dst_count = resolve_domain(raw->match.dst_fqdn, &dst_ips);
            if (dst_count == 0) {
                fprintf(stderr, "[lfw] Warning: failed to resolve FQDN '%s'\n", raw->match.dst_fqdn);
                free(src_ips);
                continue;
            }
        }

        int loop_src = src_count > 0 ? src_count : 1;
        int loop_dst = dst_count > 0 ? dst_count : 1;

        for (int s = 0; s < loop_src; s++) {
            for (int d = 0; d < loop_dst; d++) {
                lfw_rule_t rule = *raw;

                if (raw->match.has_src_fqdn) {
                    rule.match.src_ip = src_ips[s].ip;
                    rule.match.src_mask = src_ips[s].mask;
                    rule.match.match_src_ip = true;
                }
                if (raw->match.has_dst_fqdn) {
                    rule.match.dst_ip = dst_ips[d].ip;
                    rule.match.dst_mask = dst_ips[d].mask;
                    rule.match.match_dst_ip = true;
                }

                if (rule.match.match_src_ip && rule.match.match_dst_ip) {
                    if (rule.match.src_ip.ip_version != rule.match.dst_ip.ip_version) {
                        continue;
                    }
                    rule.match.ip_version = rule.match.src_ip.ip_version;
                } else if (rule.match.match_src_ip) {
                    rule.match.ip_version = rule.match.src_ip.ip_version;
                } else if (rule.match.match_dst_ip) {
                    rule.match.ip_version = rule.match.dst_ip.ip_version;
                } else {
                    rule.match.ip_version = 0;
                }

                bool dup = false;
                for (lfw_u32 k = 0; k < count; k++) {
                    if (memcmp(&list[k].match, &rule.match, sizeof(lfw_rule_match_t)) == 0 &&
                        list[k].action == rule.action) {
                        dup = true;
                        break;
                    }
                }
                if (dup) continue;

                if (count >= cap) {
                    cap *= 2;
                    lfw_rule_t *tmp = realloc(list, cap * sizeof(lfw_rule_t));
                    if (!tmp) {
                        free(src_ips);
                        free(dst_ips);
                        free(list);
                        return LFW_ERR_NO_MEMORY;
                    }
                    list = tmp;
                }
                list[count++] = rule;
            }
        }
        free(src_ips);
        free(dst_ips);
    }

    *expanded_rules = list;
    *expanded_count = count;
    return LFW_OK;
}
