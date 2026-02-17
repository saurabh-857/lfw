#include <stdio.h>
#include <stdlib.h>

#include "lfw_config.h"
#include "lfw_engine.h"
#include "lfw_nfqueue.h"
#include "lfw_state.h"

int main(int argc, char **argv)
{
    const char *config_path = "/etc/lfw/lfw.rules";

    if (argc > 1)
        config_path = argv[1];

    lfw_rule_t *rules = NULL;
    lfw_u32 rule_count = 0;
    lfw_action_t default_action = LFW_ACTION_DROP;

    lfw_status_t st = lfw_config_load_file(
        config_path,
        &default_action,
        &rules,
        &rule_count
    );

    if (st != LFW_OK) {
        fprintf(stderr,
                "[lfw] failed to load config: %s\n",
                config_path);
        return 1;
    }

    lfw_state_t *state = lfw_state_create();
    if (!state) {
        fprintf(stderr,
                "[lfw] failed to create state table\n");
        free(rules);
        return 1;
    }

    lfw_engine_t engine = {
        .config = {
            .default_action = default_action
        },
        .ruleset = {
            .rules = rules,
            .rule_count = rule_count
        },
        .connection_state = state
    };

    printf("[lfw] starting\n");
    printf("[lfw] config: %s\n", config_path);
    printf("[lfw] rules: %u\n", rule_count);
    printf("[lfw] default: %s\n",
            default_action == LFW_ACTION_ACCEPT ?
            "ACCEPT" : "DROP");

    st = lfw_nfqueue_run(&engine, 0);

    lfw_state_destroy(state);
    lfw_config_free_rules(rules);

    if (st != LFW_OK)
        return 1;

    printf("\n[lfw] shutdown complete\n");

    return 0;
}
