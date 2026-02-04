#include <stdio.h>
#include <pcap.h>

#include "lfw_engine.h"
#include "lfw_packet_parse.h"

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap error: %s\n", errbuf);
        return 1;
    }

    /* Example: empty ruleset, default DROP */
    lfw_engine_t engine = {
        .config = { .default_action = LFW_ACTION_DROP },
        .ruleset = { NULL, 0 }
    };

    while ((rc = pcap_next_ex(pcap, &hdr, &data)) == 1) {
        lfw_packet_t pkt;
        lfw_status_t st;

        /* Skip Ethernet header (14 bytes) */
        if (hdr->caplen <= 14)
            continue;

        st = lfw_parse_ipv4_packet(
            data + 14,
            hdr->caplen - 14,
            LFW_DIR_INBOUND,
            &pkt
        );

        if (st != LFW_OK)
            continue;

        lfw_verdict_t v = lfw_engine_evaluate(&engine, &pkt);

        printf("packet verdict: %s\n",
               v == LFW_VERDICT_ACCEPT ? "ACCEPT" : "DROP");
    }

    pcap_close(pcap);
    return 0;
}
