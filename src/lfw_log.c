// SPDX-License-Identifier: GPL-3.0-only

#include "lfw_log.h"
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <string.h>

static lfw_log_target_t g_log_target = LFW_LOG_CONSOLE;
static lfw_loglevel_t g_log_level = LFW_LOG_OPTIMAL;

void lfw_log_init(lfw_log_target_t target)
{
    g_log_target = target;
    if (g_log_target == LFW_LOG_SYSLOG) {
        openlog("lfw", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }
}

void lfw_log_close(void)
{
    if (g_log_target == LFW_LOG_SYSLOG) {
        closelog();
    }
}

static void format_tcp_flags(lfw_u8 flags, char *buf, size_t buf_len)
{
    size_t idx = 0;
    if (idx < buf_len - 1 && (flags & 0x02)) buf[idx++] = 'S'; // SYN
    if (idx < buf_len - 1 && (flags & 0x10)) buf[idx++] = 'A'; // ACK
    if (idx < buf_len - 1 && (flags & 0x01)) buf[idx++] = 'F'; // FIN
    if (idx < buf_len - 1 && (flags & 0x04)) buf[idx++] = 'R'; // RST
    if (idx < buf_len - 1 && (flags & 0x08)) buf[idx++] = 'P'; // PSH
    if (idx < buf_len - 1 && (flags & 0x20)) buf[idx++] = 'U'; // URG
    buf[idx] = '\0';
}

void lfw_log_packet(const lfw_packet_t *pkt, lfw_verdict_t verdict)
{
    if (!pkt)
        return;

    char src_ip[48];
    char dst_ip[48];

    if (pkt->ip.src.ip_version == 4) {
        struct in_addr src_addr = { .s_addr = pkt->ip.src.v4.addr };
        struct in_addr dst_addr = { .s_addr = pkt->ip.dst.v4.addr };

        if (!inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip))) {
            snprintf(src_ip, sizeof(src_ip), "invalid");
        }
        if (!inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip))) {
            snprintf(dst_ip, sizeof(dst_ip), "invalid");
        }
    } else {
        struct in6_addr src_addr;
        struct in6_addr dst_addr;
        memcpy(&src_addr, pkt->ip.src.v6.addr, 16);
        memcpy(&dst_addr, pkt->ip.dst.v6.addr, 16);

        if (!inet_ntop(AF_INET6, &src_addr, src_ip, sizeof(src_ip))) {
            snprintf(src_ip, sizeof(src_ip), "invalid");
        }
        if (!inet_ntop(AF_INET6, &dst_addr, dst_ip, sizeof(dst_ip))) {
            snprintf(dst_ip, sizeof(dst_ip), "invalid");
        }
    }

    const char *proto = "any";
    if (pkt->protocol == LFW_PROTO_TCP)  proto = "tcp";
    else if (pkt->protocol == LFW_PROTO_UDP)  proto = "udp";
    else if (pkt->protocol == LFW_PROTO_ICMP) proto = "icmp";
    else if (pkt->protocol == LFW_PROTO_IGMP) proto = "igmp";
    else if (pkt->protocol == LFW_PROTO_ICMPV6) proto = "icmpv6";
    else if (pkt->protocol == LFW_PROTO_ESP) proto = "esp";
    else if (pkt->protocol == LFW_PROTO_AH) proto = "ah";

    const char *dir = "unknown";
    if (pkt->direction == LFW_DIR_INBOUND)  dir = "in";
    if (pkt->direction == LFW_DIR_OUTBOUND) dir = "out";

    const char *verdict_str = (verdict == LFW_VERDICT_ACCEPT) ? "ALLOW" : "DENY";

    unsigned short sport = 0;
    unsigned short dport = 0;

    if (pkt->protocol == LFW_PROTO_TCP || pkt->protocol == LFW_PROTO_UDP) {
        sport = ntohs(pkt->l4.src_port.port);
        dport = ntohs(pkt->l4.dst_port.port);
    }

    char flag_buf[16] = "";
    if (pkt->protocol == LFW_PROTO_TCP) {
        char flags_str[8];
        format_tcp_flags(pkt->tcp_flags, flags_str, sizeof(flags_str));
        snprintf(flag_buf, sizeof(flag_buf), " [%s]", flags_str);
    }

    const char *state_str = "";
    if (pkt->is_established) {
        state_str = " (EST)";
    } else if (pkt->is_new_connection) {
        state_str = " (NEW)";
    }

    if (g_log_target == LFW_LOG_SYSLOG) {
        syslog(LOG_INFO, "%-5s %-3s %-4s %15s:%-5u -> %15s:%-5u%s%s",
               verdict_str, dir, proto, src_ip, sport, dst_ip, dport, flag_buf, state_str);
    } else {
        printf("[lfw] %-5s %-3s %-4s %15s:%-5u -> %15s:%-5u%s%s\n",
               verdict_str, dir, proto, src_ip, sport, dst_ip, dport, flag_buf, state_str);
    }
}

void lfw_log_info(const char *fmt, ...)
{
    if (g_log_level < LFW_LOG_OPTIMAL)
        return;
    va_list args;
    va_start(args, fmt);
    if (g_log_target == LFW_LOG_SYSLOG) {
        vsyslog(LOG_INFO, fmt, args);
    } else {
        printf("[lfw] INFO: ");
        vprintf(fmt, args);
        printf("\n");
    }
    va_end(args);
}

void lfw_log_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    if (g_log_target == LFW_LOG_SYSLOG) {
        vsyslog(LOG_ERR, fmt, args);
    } else {
        fprintf(stderr, "[lfw] ERROR: ");
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    }
    va_end(args);
}

void lfw_log_debug(const char *fmt, ...)
{
    if (g_log_level < LFW_LOG_SUPER_MAX)
        return;
    va_list args;
    va_start(args, fmt);
    if (g_log_target == LFW_LOG_SYSLOG) {
        vsyslog(LOG_DEBUG, fmt, args);
    } else {
        printf("[lfw] DEBUG: ");
        vprintf(fmt, args);
        printf("\n");
    }
    va_end(args);
}

void lfw_log_set_level(lfw_loglevel_t level)
{
    g_log_level = level;
}

lfw_loglevel_t lfw_log_get_level(void)
{
    return g_log_level;
}
