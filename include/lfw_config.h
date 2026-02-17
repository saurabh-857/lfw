#ifndef LFW_CONFIG_H
#define LFW_CONFIG_H

#include "lfw_rules.h"
#include "lfw_types.h"

// Load rules from file
lfw_status_t lfw_config_load_file(
    const char *path,
    lfw_action_t *default_action,
    lfw_rule_t **rules_out,
    lfw_u32 *rule_count_out
);

// Free allocated rules
void lfw_config_free_rules(lfw_rule_t *rules);

#endif
