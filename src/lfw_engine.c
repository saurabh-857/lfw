#include "lfw_engine.h"
#include "lfw_state.h"

// Convert rule action to verdict
static inline lfw_verdict_t action_to_verdict(lfw_action_t action)
{
    if (action == LFW_ACTION_ACCEPT)
        return LFW_VERDICT_ACCEPT;

    return LFW_VERDICT_DROP; // fail closed
}

lfw_verdict_t lfw_engine_evaluate(
    const lfw_engine_t *engine,
    const lfw_packet_t *packet)
{
    if (!engine || !packet)
        return LFW_VERDICT_DROP;

    // If state tracking enabled, allow established flows
    if (engine->connection_state) {
        if (lfw_state_established(engine->connection_state, packet))
            return LFW_VERDICT_ACCEPT;
    }

    // Evaluate rules in order
    for (lfw_u32 i = 0; i < engine->ruleset.rule_count; i++) {

        const lfw_rule_t *rule = &engine->ruleset.rules[i];

        if (!lfw_rule_match(rule, packet))
            continue;

        lfw_verdict_t verdict = action_to_verdict(rule->action);

        // If accepting a new connection, add to state table
        if (verdict == LFW_VERDICT_ACCEPT &&
            engine->connection_state &&
            packet->is_new_connection)
        {
            lfw_state_add(engine->connection_state, packet);
        }

        return verdict;
    }

    // No rule matched -> apply default policy
    lfw_verdict_t default_verdict =
        action_to_verdict(engine->config.default_action);

    if (default_verdict == LFW_VERDICT_ACCEPT &&
        engine->connection_state &&
        packet->is_new_connection)
    {
        lfw_state_add(engine->connection_state, packet);
    }

    return default_verdict;
}
