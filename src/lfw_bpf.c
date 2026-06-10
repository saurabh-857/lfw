// SPDX-License-Identifier: GPL-3.0-only

#define __KERNEL__
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "lfw_bpf_shared.h"

// Connection tracking timeouts in nanoseconds
#define TCP_TIMEOUT_SYN_SENT_NS (20ULL * 1000000000ULL)
#define TCP_TIMEOUT_SYN_RECV_NS (20ULL * 1000000000ULL)
#define TCP_TIMEOUT_FIN_WAIT_NS (30ULL * 1000000000ULL)
#define TCP_TIMEOUT_ESTABLISHED_NS (300ULL * 1000000000ULL)
#define UDP_TIMEOUT_NS (60ULL * 1000000000ULL)

// Map declarations (IPv4)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conntrack_key);
    __type(value, struct conntrack_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key);
    __type(value, struct rule_mask);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} src_ip_trie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm_key);
    __type(value, struct rule_mask);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dst_ip_trie SEC(".maps");

// Map declarations (IPv6)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conntrack_key_v6);
    __type(value, struct conntrack_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm6_key);
    __type(value, struct rule_mask);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} src_ip6_trie SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct lpm6_key);
    __type(value, struct rule_mask);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dst_ip6_trie SEC(".maps");

// General config & telemetry maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct bpf_rule);
} rules_details_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events_ringbuf SEC(".maps");

// IPv6 Address Helper Comparison
static inline int ip6_cmp(const struct in6_addr *a, const struct in6_addr *b)
{
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (a->s6_addr[i] < b->s6_addr[i]) return -1;
        if (a->s6_addr[i] > b->s6_addr[i]) return 1;
    }
    return 0;
}

static inline int is_loopback_v4(__be32 ip) {
    return (ip & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000);
}

static inline int is_loopback_v6(const struct in6_addr *ip) {
    if (ip->s6_addr[15] != 1) return 0;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (ip->s6_addr[i] != 0) return 0;
    }
    return 1;
}

static __attribute__((noinline)) int do_ipv4_filter(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if ((void *)((__u8 *)ip + ip_hdr_len) > data_end)
        return TC_ACT_OK;

    __be32 src_ip = ip->saddr;
    __be32 dst_ip = ip->daddr;
    __u8 proto = ip->protocol;
    __u8 lfw_proto = proto;
    __be16 src_port = 0;
    __be16 dst_port = 0;
    __u8 tcp_syn = 0, tcp_ack = 0, tcp_fin = 0, tcp_rst = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((__u8 *)ip + ip_hdr_len);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;
        __u8 tcp_flags = ((__u8 *)tcp)[13];
        tcp_syn = (tcp_flags & 0x02) != 0;
        tcp_ack = (tcp_flags & 0x10) != 0;
        tcp_fin = (tcp_flags & 0x01) != 0;
        tcp_rst = (tcp_flags & 0x04) != 0;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((__u8 *)ip + ip_hdr_len);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // Conntrack
    __u8 conntrack_found = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = skb->len;
    struct conntrack_key key = {};

    if (src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port)) {
        key.src_ip   = src_ip;
        key.dst_ip   = dst_ip;
        key.src_port = src_port;
        key.dst_port = dst_port;
    } else {
        key.src_ip   = dst_ip;
        key.dst_ip   = src_ip;
        key.src_port = dst_port;
        key.dst_port = src_port;
    }
    key.proto = lfw_proto;

    if (lfw_proto == IPPROTO_TCP || lfw_proto == IPPROTO_UDP) {
        struct conntrack_val *val = bpf_map_lookup_elem(&conntrack_map, &key);
        if (val) {
            __u64 timeout = UDP_TIMEOUT_NS;
            if (lfw_proto == IPPROTO_TCP) { // TCP
                if (val->state == LFW_TCP_STATE_SYN_SENT)
                    timeout = TCP_TIMEOUT_SYN_SENT_NS;
                else if (val->state == LFW_TCP_STATE_SYN_RECV)
                    timeout = TCP_TIMEOUT_SYN_RECV_NS;
                else if (val->state == LFW_TCP_STATE_FIN_WAIT)
                    timeout = TCP_TIMEOUT_FIN_WAIT_NS;
                else
                    timeout = TCP_TIMEOUT_ESTABLISHED_NS;
            }

            if (now <= val->last_seen || now - val->last_seen <= timeout) {
                conntrack_found = 1;
                val->last_seen = now;
                val->bytes    += pkt_len;
                val->packets  += 1;

                if (lfw_proto == IPPROTO_TCP) {
                    if (tcp_rst) {
                        val->state = LFW_TCP_STATE_CLOSED;
                    } else if (val->state == LFW_TCP_STATE_SYN_SENT && tcp_syn && tcp_ack) {
                        val->state = LFW_TCP_STATE_SYN_RECV;
                    } else if (val->state == LFW_TCP_STATE_SYN_RECV && tcp_ack && !tcp_syn) {
                        val->state = LFW_TCP_STATE_ESTABLISHED;
                    } else if (val->state == LFW_TCP_STATE_ESTABLISHED && tcp_fin) {
                        val->state = LFW_TCP_STATE_FIN_WAIT;
                    } else if (val->state == LFW_TCP_STATE_FIN_WAIT && (tcp_ack || tcp_fin)) {
                        val->state = LFW_TCP_STATE_CLOSED;
                    }
                }

                if (lfw_proto == IPPROTO_UDP) {
                    if ((val->state == 0 && src_ip == key.dst_ip) ||
                        (val->state == 1 && src_ip == key.src_ip)) {
                        val->state = 2; // Replied
                        struct lfw_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct lfw_event), 0);
                        if (event) {
                            event->ip_version = 4;
                            event->src_ip.v4 = src_ip;
                            event->dst_ip.v4 = dst_ip;
                            event->src_port = src_port;
                            event->dst_port = dst_port;
                            event->proto = lfw_proto;
                            event->action = val->action;
                            event->pkt_len = pkt_len;
                            event->timestamp = now;
                            bpf_ringbuf_submit(event, 0);
                        }
                    }
                }

                __u32 act = val->action;

                if (act == 1) return TC_ACT_OK;
                else return TC_ACT_SHOT;
            } else {
                bpf_map_delete_elem(&conntrack_map, &key);
            }
        }
    }

    // Out-of-state checks
    if (lfw_proto == IPPROTO_TCP && !conntrack_found && !is_loopback_v4(src_ip)) {
        if (!tcp_syn || tcp_ack || tcp_rst || tcp_fin) {
            struct lfw_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct lfw_event), 0);
            if (event) {
                event->ip_version = 4;
                event->src_ip.v4 = src_ip;
                event->dst_ip.v4 = dst_ip;
                event->src_port = src_port;
                event->dst_port = dst_port;
                event->proto = lfw_proto;
                event->action = 2; // DROP
                event->pkt_len = pkt_len;
                event->timestamp = now;
                bpf_ringbuf_submit(event, 0);
            }
            return TC_ACT_SHOT;
        }
    }

    // Rules evaluation
    struct rule_mask intersected = {};
    __u8 src_matched = 0;
    {
        struct lpm_key lpm_key = { .prefixlen = 32, .ip = src_ip };
        struct rule_mask *src_mask = bpf_map_lookup_elem(&src_ip_trie, &lpm_key);
        if (src_mask) {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                intersected.bits[i] = src_mask->bits[i];
            }
            src_matched = 1;
        }
    }
    if (src_matched) {
        struct lpm_key lpm_key = { .prefixlen = 32, .ip = dst_ip };
        struct rule_mask *dst_mask = bpf_map_lookup_elem(&dst_ip_trie, &lpm_key);
        if (dst_mask) {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                intersected.bits[i] &= dst_mask->bits[i];
            }
        } else {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                intersected.bits[i] = 0;
            }
        }
    }

    __u8 decision_action = 0;
    struct bpf_rule *matched_rule = NULL;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < 4; i++) {
        __u64 mask_val = intersected.bits[i];
        #pragma clang loop unroll(disable)
        for (int j = 0; j < 16; j++) {
            if (mask_val == 0) break;
            int bit_idx = __builtin_ctzll(mask_val);
            __u32 rule_idx = i * 64 + bit_idx;

            struct bpf_rule *rule = bpf_map_lookup_elem(&rules_details_map, &rule_idx);
            if (rule) {
                __u8 version_match = (rule->ip_version == 0 || rule->ip_version == 4);
                if (version_match && (rule->protocol == 0 || rule->protocol == lfw_proto)) {
                    __u8 port_match = 1;
                    if (lfw_proto == IPPROTO_TCP || lfw_proto == IPPROTO_UDP) {
                        __u16 s_port = bpf_ntohs(src_port);
                        __u16 d_port = bpf_ntohs(dst_port);
                        if (rule->match_src_port) {
                            if (s_port < rule->src_port_min || s_port > rule->src_port_max) port_match = 0;
                        }
                        if (rule->match_dst_port) {
                            if (d_port < rule->dst_port_min || d_port > rule->dst_port_max) port_match = 0;
                        }
                    }
                    if (port_match) {
                        decision_action = rule->action;
                        matched_rule = rule;
                        break;
                    }
                }
            }
            mask_val &= (mask_val - 1);
        }
        if (decision_action != 0) break;
    }

    if (decision_action == 0) {
        __u32 config_idx_def = 0;
        __u32 *p_default_action = bpf_map_lookup_elem(&config_map, &config_idx_def);
        decision_action = p_default_action ? (__u8)*p_default_action : 2;
    }

    if (matched_rule) {
        __sync_fetch_and_add(&matched_rule->hit_count, 1);
        __sync_fetch_and_add(&matched_rule->byte_count, pkt_len);
    }

    if (decision_action != 0) {
        struct lfw_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct lfw_event), 0);
        if (event) {
            event->ip_version = 4;
            event->src_ip.v4 = src_ip;
            event->dst_ip.v4 = dst_ip;
            event->src_port = src_port;
            event->dst_port = dst_port;
            event->proto = lfw_proto;
            event->action = decision_action;
            event->pkt_len = pkt_len;
            event->timestamp = now;
            bpf_ringbuf_submit(event, 0);
        }
    }

    if (decision_action == 1 && (lfw_proto == IPPROTO_TCP || lfw_proto == IPPROTO_UDP)) {
        __u8 init_state = 0;
        if (lfw_proto == IPPROTO_TCP) {
            init_state = LFW_TCP_STATE_SYN_SENT;
        } else {
            init_state = (src_ip == key.src_ip) ? 0 : 1;
        }
        struct conntrack_val new_val = {
            .last_seen = now,
            .bytes     = pkt_len,
            .packets   = 1,
            .action    = 1,
            .state     = init_state,
        };
        bpf_map_update_elem(&conntrack_map, &key, &new_val, BPF_ANY);
    }

    if (decision_action == 1) return TC_ACT_OK;
    else return TC_ACT_SHOT;
}

static __attribute__((noinline)) int do_ipv6_filter(struct __sk_buff *skb, struct ethhdr *eth, void *data_end)
{
    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return TC_ACT_OK;

    const struct in6_addr *saddr = &ip6->saddr;
    const struct in6_addr *daddr = &ip6->daddr;
    __u8 proto = ip6->nexthdr;
    __u8 lfw_proto = proto;
    __be16 src_port = 0;
    __be16 dst_port = 0;
    __u8 tcp_syn = 0, tcp_ack = 0, tcp_fin = 0, tcp_rst = 0;

    __u32 ip_hdr_len = 40;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 5; i++) {
        if (proto == 0 || proto == 43 || proto == 60 || proto == 44 || proto == 51) {
            if (ip_hdr_len > 256)
                return TC_ACT_OK;

            __u8 *ext = (void *)((__u8 *)ip6 + ip_hdr_len);
            if ((void *)(ext + 2) > data_end)
                return TC_ACT_OK;

            __u8 next_proto = ext[0];
            __u32 ext_len = 8;
            if (proto == 0 || proto == 43 || proto == 60) {
                ext_len = (ext[1] + 1) * 8;
            } else if (proto == 51) {
                ext_len = (ext[1] + 2) * 4;
            }

            if ((void *)(ext + ext_len) > data_end)
                return TC_ACT_OK;

            ip_hdr_len += ext_len;
            proto = next_proto;
            lfw_proto = next_proto;
        } else {
            break;
        }
    }

    if (lfw_proto == IPPROTO_TCP) {
        if (ip_hdr_len > 256)
            return TC_ACT_OK;
        struct tcphdr *tcp = (void *)((__u8 *)ip6 + ip_hdr_len);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;
        __u8 tcp_flags = ((__u8 *)tcp)[13];
        tcp_syn = (tcp_flags & 0x02) != 0;
        tcp_ack = (tcp_flags & 0x10) != 0;
        tcp_fin = (tcp_flags & 0x01) != 0;
        tcp_rst = (tcp_flags & 0x04) != 0;
    } else if (lfw_proto == IPPROTO_UDP) {
        if (ip_hdr_len > 256)
            return TC_ACT_OK;
        struct udphdr *udp = (void *)((__u8 *)ip6 + ip_hdr_len);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;
    }    // Conntrack
    __u8 conntrack_found = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = skb->len;
    struct conntrack_key_v6 key6 = {};

    int cmp = ip6_cmp(saddr, daddr);
    if (cmp < 0 || (cmp == 0 && src_port <= dst_port)) {
        __builtin_memcpy(&key6.src_ip, saddr, sizeof(struct in6_addr));
        __builtin_memcpy(&key6.dst_ip, daddr, sizeof(struct in6_addr));
        key6.src_port = src_port;
        key6.dst_port = dst_port;
    } else {
        __builtin_memcpy(&key6.src_ip, daddr, sizeof(struct in6_addr));
        __builtin_memcpy(&key6.dst_ip, saddr, sizeof(struct in6_addr));
        key6.src_port = dst_port;
        key6.dst_port = src_port;
    }
    key6.proto = lfw_proto;

    if (lfw_proto == IPPROTO_TCP || lfw_proto == IPPROTO_UDP) {
        struct conntrack_val *val = bpf_map_lookup_elem(&conntrack_map_v6, &key6);
        if (val) {
            __u64 timeout = UDP_TIMEOUT_NS;
            if (lfw_proto == IPPROTO_TCP) { // TCP
                if (val->state == LFW_TCP_STATE_SYN_SENT)
                    timeout = TCP_TIMEOUT_SYN_SENT_NS;
                else if (val->state == LFW_TCP_STATE_SYN_RECV)
                    timeout = TCP_TIMEOUT_SYN_RECV_NS;
                else if (val->state == LFW_TCP_STATE_FIN_WAIT)
                    timeout = TCP_TIMEOUT_FIN_WAIT_NS;
                else
                    timeout = TCP_TIMEOUT_ESTABLISHED_NS;
            }

            if (now <= val->last_seen || now - val->last_seen <= timeout) {
                conntrack_found = 1;
                val->last_seen = now;
                val->bytes    += pkt_len;
                val->packets  += 1;

                if (lfw_proto == IPPROTO_TCP) {
                    if (tcp_rst) {
                        val->state = LFW_TCP_STATE_CLOSED;
                    } else if (val->state == LFW_TCP_STATE_SYN_SENT && tcp_syn && tcp_ack) {
                        val->state = LFW_TCP_STATE_SYN_RECV;
                    } else if (val->state == LFW_TCP_STATE_SYN_RECV && tcp_ack && !tcp_syn) {
                        val->state = LFW_TCP_STATE_ESTABLISHED;
                    } else if (val->state == LFW_TCP_STATE_ESTABLISHED && tcp_fin) {
                        val->state = LFW_TCP_STATE_FIN_WAIT;
                    } else if (val->state == LFW_TCP_STATE_FIN_WAIT && (tcp_ack || tcp_fin)) {
                        val->state = LFW_TCP_STATE_CLOSED;
                    }
                }

                if (lfw_proto == IPPROTO_UDP) {
                    if ((val->state == 0 && ip6_cmp(saddr, &key6.dst_ip) == 0) ||
                        (val->state == 1 && ip6_cmp(saddr, &key6.src_ip) == 0)) {
                        val->state = 2; // LFW_UDP_STATE_REPLIED
                        struct lfw_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct lfw_event), 0);
                        if (event) {
                            event->ip_version = 6;
                            __builtin_memcpy(&event->src_ip.v6, saddr, sizeof(struct in6_addr));
                            __builtin_memcpy(&event->dst_ip.v6, daddr, sizeof(struct in6_addr));
                            event->src_port = src_port;
                            event->dst_port = dst_port;
                            event->proto = lfw_proto;
                            event->action = val->action;
                            event->pkt_len = pkt_len;
                            event->timestamp = now;
                            bpf_ringbuf_submit(event, 0);
                        }
                    }
                }

                __u32 act = val->action;

                if (act == 1) return TC_ACT_OK;
                else return TC_ACT_SHOT;
            } else {
                bpf_map_delete_elem(&conntrack_map_v6, &key6);
            }
        }
    }

    // Out-of-state checks
    if (lfw_proto == IPPROTO_TCP && !conntrack_found && !is_loopback_v6(saddr)) {
        if (!tcp_syn || tcp_ack || tcp_rst || tcp_fin) {
            struct lfw_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct lfw_event), 0);
            if (event) {
                event->ip_version = 6;
                __builtin_memcpy(&event->src_ip.v6, saddr, sizeof(struct in6_addr));
                __builtin_memcpy(&event->dst_ip.v6, daddr, sizeof(struct in6_addr));
                event->src_port = src_port;
                event->dst_port = dst_port;
                event->proto = lfw_proto;
                event->action = 2; // DROP
                event->pkt_len = pkt_len;
                event->timestamp = now;
                bpf_ringbuf_submit(event, 0);
            }
            return TC_ACT_SHOT;
        }
    }

    // Rules evaluation
    struct rule_mask intersected = {};
    __u8 src_matched = 0;
    {
        struct lpm6_key lpm_key = { .prefixlen = 128 };
        __builtin_memcpy(&lpm_key.ip, saddr, sizeof(struct in6_addr));
        struct rule_mask *src_mask = bpf_map_lookup_elem(&src_ip6_trie, &lpm_key);
        if (src_mask) {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                intersected.bits[i] = src_mask->bits[i];
            }
            src_matched = 1;
        }
    }
    if (src_matched) {
        struct lpm6_key lpm_key = { .prefixlen = 128 };
        __builtin_memcpy(&lpm_key.ip, daddr, sizeof(struct in6_addr));
        struct rule_mask *dst_mask = bpf_map_lookup_elem(&dst_ip6_trie, &lpm_key);
        if (dst_mask) {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                intersected.bits[i] &= dst_mask->bits[i];
            }
        } else {
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                intersected.bits[i] = 0;
            }
        }
    }

    __u8 decision_action = 0;
    struct bpf_rule *matched_rule = NULL;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < 4; i++) {
        __u64 mask_val = intersected.bits[i];
        #pragma clang loop unroll(disable)
        for (int j = 0; j < 16; j++) {
            if (mask_val == 0) break;
            int bit_idx = __builtin_ctzll(mask_val);
            __u32 rule_idx = i * 64 + bit_idx;

            struct bpf_rule *rule = bpf_map_lookup_elem(&rules_details_map, &rule_idx);
            if (rule) {
                __u8 version_match = (rule->ip_version == 0 || rule->ip_version == 6);
                if (version_match && (rule->protocol == 0 || rule->protocol == lfw_proto)) {
                    __u8 port_match = 1;
                    if (lfw_proto == IPPROTO_TCP || lfw_proto == IPPROTO_UDP) {
                        __u16 s_port = bpf_ntohs(src_port);
                        __u16 d_port = bpf_ntohs(dst_port);
                        if (rule->match_src_port) {
                            if (s_port < rule->src_port_min || s_port > rule->src_port_max) port_match = 0;
                        }
                        if (rule->match_dst_port) {
                            if (d_port < rule->dst_port_min || d_port > rule->dst_port_max) port_match = 0;
                        }
                    }
                    if (port_match) {
                        decision_action = rule->action;
                        matched_rule = rule;
                        break;
                    }
                }
            }
            mask_val &= (mask_val - 1);
        }
        if (decision_action != 0) break;
    }

    if (decision_action == 0) {
        __u32 config_idx_def = 0;
        __u32 *p_default_action = bpf_map_lookup_elem(&config_map, &config_idx_def);
        decision_action = p_default_action ? (__u8)*p_default_action : 2;
    }

    if (matched_rule) {
        __sync_fetch_and_add(&matched_rule->hit_count, 1);
        __sync_fetch_and_add(&matched_rule->byte_count, pkt_len);
    }

    if (decision_action != 0) {
        struct lfw_event *event = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct lfw_event), 0);
        if (event) {
            event->ip_version = 6;
            __builtin_memcpy(&event->src_ip.v6, saddr, sizeof(struct in6_addr));
            __builtin_memcpy(&event->dst_ip.v6, daddr, sizeof(struct in6_addr));
            event->src_port = src_port;
            event->dst_port = dst_port;
            event->proto = lfw_proto;
            event->action = decision_action;
            event->pkt_len = pkt_len;
            event->timestamp = now;
            bpf_ringbuf_submit(event, 0);
        }
    }

    if (decision_action == 1 && (lfw_proto == IPPROTO_TCP || lfw_proto == IPPROTO_UDP)) {
        __u8 init_state = 0;
        if (lfw_proto == IPPROTO_TCP) {
            init_state = LFW_TCP_STATE_SYN_SENT;
        } else {
            init_state = (ip6_cmp(saddr, &key6.src_ip) == 0) ? 0 : 1;
        }
        struct conntrack_val new_val = {
            .last_seen = now,
            .bytes     = pkt_len,
            .packets   = 1,
            .action    = 1,
            .state     = init_state,
        };
        bpf_map_update_elem(&conntrack_map_v6, &key6, &new_val, BPF_ANY);
    }

    if (decision_action == 1) return TC_ACT_OK;
    else return TC_ACT_SHOT;
}

SEC("tc")
int lfw_tc_filter(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    if (h_proto == ETH_P_IP) {
        return do_ipv4_filter(skb, eth, data_end);
    } else if (h_proto == ETH_P_IPV6) {
        return do_ipv6_filter(skb, eth, data_end);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
