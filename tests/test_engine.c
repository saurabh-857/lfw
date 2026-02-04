#include <arpa/inet.h>
#include "test_utils.h"
#include "lfw_engine.h"

static void test_engine_drop(void)
{
    lfw_rule_t rules[] = {
        {
            .match = {
                .protocol = LFW_PROTO_TCP,
                .dst_port = { .port = htons(22) },
                .match_dst_port = true
            },
            .action = LFW_ACTION_DROP
        }
    };

    lfw_engine_t engine = {
        .config = { .default_action = LFW_ACTION_ACCEPT },
        .ruleset = { rules, 1 }
    };

    lfw_packet_t pkt = {
        .protocol = LFW_PROTO_TCP,
        .l4.dst_port = { .port = htons(22) }
    };

    lfw_verdict_t v = lfw_engine_evaluate(&engine, &pkt);

    TEST_ASSERT(v == LFW_VERDICT_DROP, "engine failed to drop packet");

    TEST_PASS("engine drop verdict");
}

void run_engine_tests(void)
{
    test_engine_drop();
}
