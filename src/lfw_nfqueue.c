#include "lfw_nfqueue.h"
#include "lfw_packet_parse.h"

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global stop flag for graceful shutdown
static volatile sig_atomic_t g_running = 1;

// ------------------------------
// Signal handler
// ------------------------------

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

// ------------------------------
// Logging
// ------------------------------

static void log_packet(const lfw_packet_t *pkt,
                       lfw_verdict_t verdict)
{
    char src_ip[16];
    char dst_ip[16];

    uint32_t src = ntohl(pkt->ip4.src.addr);
    uint32_t dst = ntohl(pkt->ip4.dst.addr);

    snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u",
            (src >> 24) & 0xFF,
            (src >> 16) & 0xFF,
            (src >> 8) & 0xFF,
            src & 0xFF);

    snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u",
            (dst >> 24) & 0xFF,
            (dst >> 16) & 0xFF,
            (dst >> 8) & 0xFF,
            dst & 0xFF);

    const char *proto = "any";
    if (pkt->protocol == LFW_PROTO_TCP)  proto = "tcp";
    if (pkt->protocol == LFW_PROTO_UDP)  proto = "udp";
    if (pkt->protocol == LFW_PROTO_ICMP) proto = "icmp";

    const char *dir = "unknown";
    if (pkt->direction == LFW_DIR_INBOUND)  dir = "in";
    if (pkt->direction == LFW_DIR_OUTBOUND) dir = "out";

    const char *verdict_str =
        (verdict == LFW_VERDICT_ACCEPT) ? "ALLOW" : "DENY";

    unsigned short sport = 0;
    unsigned short dport = 0;

    if (pkt->protocol == LFW_PROTO_TCP ||
        pkt->protocol == LFW_PROTO_UDP)
    {
        sport = ntohs(pkt->l4.src_port.port);
        dport = ntohs(pkt->l4.dst_port.port);
    }

    printf("[lfw] %-5s %-3s %-4s %15s:%-5u -> %15s:%-5u\n",
           verdict_str,
           dir,
           proto,
           src_ip,
           sport,
           dst_ip,
           dport);
}

// ------------------------------
// NFQUEUE callback
// ------------------------------

static int nfqueue_callback(struct nfq_q_handle *qh,
                            struct nfgenmsg *nfmsg,
                            struct nfq_data *nfa,
                            void *data)
{
    (void)nfmsg;

    const lfw_engine_t *engine =
        (const lfw_engine_t *)data;

    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload = NULL;
    int payload_len;
    uint32_t packet_id = 0;

    lfw_packet_t packet;
    lfw_verdict_t verdict = LFW_VERDICT_DROP;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
        packet_id = ntohl(ph->packet_id);

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 0 || !payload)
        goto out;

    lfw_direction_t direction = LFW_DIR_UNKNOWN;

    if (ph) {
        switch (ph->hook) {
            case NF_INET_PRE_ROUTING:
            case NF_INET_LOCAL_IN:
                direction = LFW_DIR_INBOUND;
                break;

            case NF_INET_LOCAL_OUT:
                direction = LFW_DIR_OUTBOUND;
                break;

            default:
                direction = LFW_DIR_UNKNOWN;
                break;
        }
    }

    if (lfw_parse_ipv4_packet(payload,
                              (size_t)payload_len,
                              direction,
                              &packet) != LFW_OK)
        goto out;

    verdict = lfw_engine_evaluate(engine, &packet);

    log_packet(&packet, verdict);

out:
    return nfq_set_verdict(
        qh,
        packet_id,
        (verdict == LFW_VERDICT_ACCEPT) ? NF_ACCEPT : NF_DROP,
        0,
        NULL
    );
}

// ------------------------------
// Main NFQUEUE loop
// ------------------------------

lfw_status_t lfw_nfqueue_run(
    const lfw_engine_t *engine,
    unsigned int queue_num)
{
    if (!engine)
        return LFW_ERR_INVALID;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct nfq_handle *h = nfq_open();
    if (!h)
        return LFW_ERR_GENERIC;

    if (nfq_unbind_pf(h, AF_INET) < 0 ||
        nfq_bind_pf(h, AF_INET) < 0)
    {
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    struct nfq_q_handle *qh =
        nfq_create_queue(h,
                        queue_num,
                        &nfqueue_callback,
                        (void *)engine);

    if (!qh) {
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    if (nfq_set_mode(qh,
                    NFQNL_COPY_PACKET,
                    0xffff) < 0)
    {
        nfq_destroy_queue(qh);
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));

    while (g_running) {

        int rv = recv(fd, buf, sizeof(buf), 0);

        if (rv > 0)
            nfq_handle_packet(h, buf, rv);
        else if (rv < 0 && g_running)
            break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return LFW_OK;
}
