#include <stdio.h>
#include <pcap.h>

#include "lfw_engine.h"
#include "lfw_packet_parse.h"
#include "lfw_config.h"

/*
 * Offline pcap tester for lfw.
 *
 * Behaviour is analogous to the main daemon in src/main.c:
 *   - load rules from /etc/lfw/lfw.rules by default
 *   - optionally override rules path via CLI
 *   - evaluate each packet with the same engine logic
 *
 * Usage:
 *   lfw_pcap_test <file.pcap> [rules_file]
 *
 * If rules_file is omitted, /etc/lfw/lfw.rules is used.
 */
int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;

    const char *config_path = "/etc/lfw/lfw.rules";
    lfw_rule_t *rules = NULL;
    lfw_u32 rule_count = 0;
    lfw_action_t default_action = LFW_ACTION_ACCEPT;
    lfw_status_t status;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <file.pcap> [rules_file]\n", argv[0]);
        return 1;
    }

    if (argc == 3) {
        config_path = argv[2];
    }

    pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap error: %s\n", errbuf);
        return 1;
    }

    /* Try to load rules from the external config file (same logic as main.c). */
    status = lfw_config_load_file(config_path,
                                  &default_action,
                                  &rules,
                                  &rule_count);

    if (status != LFW_OK) {
        fprintf(stderr,
                "[lfw-pcap] warning: failed to load config '%s', "
                "falling back to default policy: deny all inbound\n",
                config_path);

        rules = NULL;
        rule_count = 0;
        default_action = LFW_ACTION_DROP;
    }

    /* Create engine using the loaded (or fallback) configuration. */
    lfw_engine_t engine = {
        .config = {
            .default_action = default_action
        },
        .ruleset = {
            .rules = rules,
            .rule_count = rule_count
        }
    };

    printf("[lfw-pcap] using rules: %s (rules: %u, default: %s)\n",
           config_path,
           engine.ruleset.rule_count,
           (engine.config.default_action == LFW_ACTION_ACCEPT) ? "ACCEPT" : "DROP");

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

    if (rules) {
        lfw_config_free_rules(rules);
    }

    return 0;
}
