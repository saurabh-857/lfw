#include <stdio.h>

#include "lfw_nfqueue.h"

/*
 * Temporary static ruleset
 */
static const lfw_rule_t rules[] = {
    /* Drop inbound SSH */
    {
        .match = {
            .protocol = LFW_PROTO_TCP,
            .dst_port = { .port = htons(22) },
            .match_dst_port = true
        },
        .action = LFW_ACTION_DROP
    }
};

int main(void)
{
    lfw_engine_t engine = {
        .config = {
            .default_action = LFW_ACTION_ACCEPT
        },
        .ruleset = {
            .rules = rules,
            .rule_count = sizeof(rules) / sizeof(rules[0])
        }
    };

    printf("[lfw] starting firewall\n");

    return lfw_nfqueue_run(&engine, 0);
}
