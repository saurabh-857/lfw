#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "lfw_nfqueue.h"
#include "lfw_packet_parse.h"

/*
 * Simple logging helper: print packet decision.
 */
static void lfw_log_packet(const lfw_packet_t *pkt, lfw_verdict_t verdict)
{
    uint32_t src = ntohl(pkt->ip4.src.addr);
    uint32_t dst = ntohl(pkt->ip4.dst.addr);
    unsigned short sport = 0;
    unsigned short dport = 0;
    const char *proto_str = "any";
    const char *verdict_str = (verdict == LFW_VERDICT_ACCEPT) ? "ALLOW" : "DENY";

    if (pkt->protocol == LFW_PROTO_TCP || pkt->protocol == LFW_PROTO_UDP) {
        sport = ntohs(pkt->l4.src_port.port);
        dport = ntohs(pkt->l4.dst_port.port);
    }

    switch (pkt->protocol) {
        case LFW_PROTO_TCP:  proto_str = "tcp";  break;
        case LFW_PROTO_UDP:  proto_str = "udp";  break;
        case LFW_PROTO_ICMP: proto_str = "icmp"; break;
        default:             proto_str = "any";  break;
    }

    printf("[lfw] %s %s %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           verdict_str,
           proto_str,
           (src >> 24) & 0xFF,
           (src >> 16) & 0xFF,
           (src >> 8)  & 0xFF,
           src & 0xFF,
           sport,
           (dst >> 24) & 0xFF,
           (dst >> 16) & 0xFF,
           (dst >> 8)  & 0xFF,
           dst & 0xFF,
           dport);
}

/*
 * NFQUEUE callback
 */
static int lfw_nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg __attribute__((unused)), struct nfq_data *nfa, void *data)
{
    const lfw_engine_t *engine = (const lfw_engine_t *)data;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload = NULL;
    int payload_len;
    uint32_t packet_id = 0;

    lfw_packet_t packet;
    lfw_verdict_t verdict = LFW_VERDICT_DROP;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        packet_id = ntohl(ph->packet_id);
    }

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 0 || !payload) {
        goto out;
    }

    if (lfw_parse_ipv4_packet(payload, (size_t)payload_len, LFW_DIR_INBOUND, &packet) != LFW_OK) {
        goto out;
    }

    verdict = lfw_engine_evaluate(engine, &packet);

    /* Log the decision for visibility during testing */
    lfw_log_packet(&packet, verdict);

out:
    return nfq_set_verdict(qh, packet_id, (verdict == LFW_VERDICT_ACCEPT) ? NF_ACCEPT : NF_DROP, 0, NULL);
}

/*
 * Start NFQUEUE loop
 */
lfw_status_t lfw_nfqueue_run(const lfw_engine_t *engine, unsigned int queue_num)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    char buf[4096] __attribute__((aligned));

    if (!engine) {                  // ensure the engine context (rules + config) is valid
        return LFW_ERR_INVALID;
    }

    h = nfq_open();                 // create a connection to Netfilter queue subsystem
    if (!h) {
        return LFW_ERR_GENERIC;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {    // unbinds (just in case)
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {      // binds the queue to IPv4 packets
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    qh = nfq_create_queue(h, queue_num, &lfw_nfqueue_cb, (void *)engine);
    if (!qh) {
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        nfq_destroy_queue(qh);
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    fd = nfq_fd(h);

    while (1) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        }
    }

    /* unreachable for now */
    nfq_destroy_queue(qh);
    nfq_close(h);
    return LFW_OK;
}
