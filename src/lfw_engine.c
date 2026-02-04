#include "lfw_engine.h"

/*
 * Convert action to verdict
 */
static lfw_verdict_t lfw_action_to_verdict(lfw_action_t action)
{
    switch (action) {
        case LFW_ACTION_ACCEPT:
            return LFW_VERDICT_ACCEPT;
        case LFW_ACTION_DROP:
            return LFW_VERDICT_DROP;
        default:
            return LFW_VERDICT_DROP;    // fail closed
    }
}

/*
 * Evaluate packet against rule engine
 */
lfw_verdict_t lfw_engine_evaluate(const lfw_engine_t *engine, const lfw_packet_t *packet)
{
    lfw_u32 i;

    if (!engine || !packet) {
        return LFW_VERDICT_DROP;
    }

    for (i = 0; i < engine->ruleset.rule_count; i++) {
        const lfw_rule_t *rule = &engine->ruleset.rules[i];

        if (lfw_rule_match(rule, packet)) {
            return lfw_action_to_verdict(rule->action);
        }
    }

    /* No rule matched → default policy */
    return lfw_action_to_verdict(engine->config.default_action);
}
