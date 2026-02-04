#include <arpa/inet.h>
#include "test_utils.h"
#include "lfw_rules.h"

static void test_rule_match_tcp_port(void)
{
    lfw_rule_t rule = {
        .match = {
            .protocol = LFW_PROTO_TCP,
            .dst_port = { .port = htons(22) },
            .match_dst_port = true
        },
        .action = LFW_ACTION_DROP
    };

    lfw_packet_t pkt = {
        .protocol = LFW_PROTO_TCP,
        .l4.dst_port = { .port = htons(22) }
    };

    TEST_ASSERT(lfw_rule_match(&rule, &pkt), "rule should match packet");

    TEST_PASS("TCP port rule match");
}

void run_rule_tests(void)
{
    test_rule_match_tcp_port();
}
