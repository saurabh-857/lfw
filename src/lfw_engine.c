#include "lfw_engine.h"
#include "lfw_state.h"

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
 * Evaluate packet against rule engine.
 * Stateful: if connection_state is set, established connections are allowed
 * without re-evaluating rules; only new connections (e.g. TCP SYN) are
 * matched against the ruleset and then added to the state table.
 */
lfw_verdict_t lfw_engine_evaluate(const lfw_engine_t *engine, const lfw_packet_t *packet)
{
    lfw_u32 i;

    if (!engine || !packet) {
        return LFW_VERDICT_DROP;
    }

    /* Stateful: packet belongs to an already-allowed connection → accept */
    if (engine->connection_state && lfw_state_established(engine->connection_state, packet)) {
        return LFW_VERDICT_ACCEPT;
    }

    /* Evaluate rules (for new connections or when stateless) */
    for (i = 0; i < engine->ruleset.rule_count; i++) {
        const lfw_rule_t *rule = &engine->ruleset.rules[i];

        if (lfw_rule_match(rule, packet)) {
            lfw_verdict_t verdict = lfw_action_to_verdict(rule->action);
            /* Stateful: record new connection when we allow it */
            if (verdict == LFW_VERDICT_ACCEPT && engine->connection_state
                && packet->is_new_connection) {
                lfw_state_add(engine->connection_state, packet);
            }
            return verdict;
        }
    }

    /* No rule matched → default policy */
    lfw_verdict_t verdict = lfw_action_to_verdict(engine->config.default_action);
    if (verdict == LFW_VERDICT_ACCEPT && engine->connection_state
        && packet->is_new_connection) {
        lfw_state_add(engine->connection_state, packet);
    }
    return verdict;
}
