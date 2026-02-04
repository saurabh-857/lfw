#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "lfw_nfqueue.h"
#include "lfw_packet_parse.h"

/*
 * NFQUEUE callback
 */
static int lfw_nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
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

    if (!engine) {
        return LFW_ERR_INVALID;
    }

    h = nfq_open();
    if (!h) {
        return LFW_ERR_GENERIC;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        nfq_close(h);
        return LFW_ERR_GENERIC;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
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
