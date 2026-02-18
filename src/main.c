#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include "lfw_config.h"
#include "lfw_engine.h"
#include "lfw_nfqueue.h"
#include "lfw_state.h"

static int rules_installed = 0;

static void add_iptables_rules()
{
    system("iptables -I PREROUTING -t mangle ! -i lo -j NFQUEUE --queue-num 0");
    system("iptables -I OUTPUT -t mangle ! -o lo -j NFQUEUE --queue-num 0");

    rules_installed = 1;
}

static void remove_iptables_rules()
{
    if (!rules_installed)
        return;

    system("iptables -D PREROUTING -t mangle ! -i lo -j NFQUEUE --queue-num 0");
    system("iptables -D OUTPUT -t mangle ! -o lo -j NFQUEUE --queue-num 0");

    rules_installed = 0;
}

static void cleanup()
{
    printf("[lfw] removing iptables rules...\n");
    remove_iptables_rules();
}

static void signal_handler(int sig)
{
    (void)sig;
    exit(0);  // triggers atexit cleanup
}

int main(int argc, char **argv)
{
    // Root privilege check
    if (geteuid() != 0) {
        fprintf(stderr, "[lfw] run as root\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    atexit(cleanup);

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

    printf("[lfw] inserting iptables rules...\n");
    add_iptables_rules();

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

