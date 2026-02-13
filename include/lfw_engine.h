#ifndef LFW_ENGINE_H
#define LFW_ENGINE_H

/*
 * lfw - Linux Firewall
 * Rule evaluation engine (supports stateful connection tracking)
 */

#include "lfw_types.h"
#include "lfw_packet.h"
#include "lfw_rules.h"

struct lfw_state;

/* ==============================
 * Engine configuration
 * ============================== */
typedef struct {
    lfw_action_t default_action;
} lfw_engine_config_t;

/* ==============================
 * Rule set
 * ============================== */
typedef struct {
    const lfw_rule_t *rules;
    lfw_u32           rule_count;
} lfw_ruleset_t;

/* ==============================
 * Engine context
 * ============================== */
typedef struct {
    lfw_engine_config_t config;
    lfw_ruleset_t       ruleset;
    struct lfw_state   *connection_state;  /* optional: stateful table; NULL = stateless */
} lfw_engine_t;

/* ==============================
 * Engine API
 * ============================== */

/*
 * Evaluate packet against ruleset.
 * Returns final verdict.
 */
lfw_verdict_t lfw_engine_evaluate(const lfw_engine_t *engine, const lfw_packet_t *packet);

#endif /* LFW_ENGINE_H */
