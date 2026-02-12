#include <stdio.h>
#include <stdlib.h>

#include "lfw_nfqueue.h"
#include "lfw_config.h"

int main(int argc, char **argv)
{
    const char *config_path = "/etc/lfw/lfw.rules";
    lfw_rule_t *rules = NULL;
    lfw_u32 rule_count = 0;
    lfw_action_t default_action = LFW_ACTION_ACCEPT;
    lfw_status_t status;

    /* Allow overriding the config path from the command line:
     *   ./lfw /path/to/custom.rules
     */
    if (argc > 1) {
        config_path = argv[1];
    }

    /* Try to load rules from the external config file. */
    status = lfw_config_load_file(config_path,
                                  &default_action,
                                  &rules,
                                  &rule_count);

    if (status != LFW_OK) {
        fprintf(stderr,
                "[lfw] warning: failed to load config '%s', "
                "falling back to default policy: deny all inbound\n",
                config_path);

        /* No explicit rules; engine will apply the default action
         * to every packet. Set default to DROP to enforce:
         *
         *   - deny incoming
         *   - no routing (handled by netfilter rules)
         *   - only outgoing traffic permitted (we only enqueue
         *     inbound packets into this NFQUEUE).
         */
        rules = NULL;
        rule_count = 0;
        default_action = LFW_ACTION_DROP;
    }

    // create engine & rules
    lfw_engine_t engine = {
        .config = {
            .default_action = default_action
        },
        .ruleset = {
            .rules = rules,
            .rule_count = rule_count
        }
    };

    printf("[lfw] starting firewall (config: %s, rules: %u, default: %s)\n",
           config_path,
           engine.ruleset.rule_count,
           (engine.config.default_action == LFW_ACTION_ACCEPT) ? "ACCEPT" : "DROP");

    // start NFQUEUE processing (blocks forever)
    status = lfw_nfqueue_run(&engine, 0);

    /* If we successfully loaded a dynamic ruleset, free it on exit.
     * In the usual case this process will run indefinitely and this
     * code is never reached, but it keeps things correct for tests
     * or controlled runs.
     */
    if (status == LFW_OK && rules) {
        lfw_config_free_rules(rules);
    }

    return (status == LFW_OK) ? 0 : 1;
}

