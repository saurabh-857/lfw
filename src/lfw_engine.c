#include "lfw_engine.h"
#include "lfw_state.h"
#include "lfw_config.h"
#include "lfw_log.h"
#include <stdio.h>
#include <arpa/inet.h>

// Convert rule action to verdict
static inline lfw_verdict_t action_to_verdict(lfw_action_t action)
{
    if (action == LFW_ACTION_ACCEPT)
        return LFW_VERDICT_ACCEPT;

    return LFW_VERDICT_DROP; // fail closed
}

lfw_verdict_t lfw_engine_evaluate(
    lfw_engine_t *engine,
    lfw_packet_t *packet)
{
    if (!engine || !packet)
        return LFW_VERDICT_DROP;

    // Initialize established flag
    packet->is_established = false;

    // If state tracking enabled, allow established flows
    if (engine->connection_state) {
        if (lfw_state_established(engine->connection_state, packet)) {
            packet->is_established = true;
            return LFW_VERDICT_ACCEPT;
        }
    }

    lfw_verdict_t verdict = LFW_VERDICT_DROP;
    bool matched = false;

    pthread_rwlock_rdlock(&engine->rules_lock);

    // Evaluate rules in order
    for (lfw_u32 i = 0; i < engine->ruleset.rule_count; i++) {
        lfw_rule_t *rule = (lfw_rule_t *)&engine->ruleset.rules[i];

        if (!lfw_rule_match(rule, packet))
            continue;

        verdict = action_to_verdict(rule->action);
        matched = true;

        // Atomically increment hits and byte count
        __sync_fetch_and_add(&rule->hit_count, 1);
        __sync_fetch_and_add(&rule->byte_count, packet->length);

        // If accepting, add to state table (state_add handles TCP/UDP check)
        if (verdict == LFW_VERDICT_ACCEPT &&
            engine->connection_state)
        {
            lfw_state_add(engine->connection_state, packet);
        }

        break;
    }

    if (!matched) {
        verdict = action_to_verdict(engine->config.default_action);

        if (verdict == LFW_VERDICT_ACCEPT &&
            engine->connection_state)
        {
            lfw_state_add(engine->connection_state, packet);
        }
    }

    pthread_rwlock_unlock(&engine->rules_lock);

    return verdict;
}

lfw_status_t lfw_engine_reload_rules(lfw_engine_t *engine)
{
    if (!engine)
        return LFW_ERR_INVALID;

    lfw_rule_t *new_rules = NULL;
    lfw_u32 new_rule_count = 0;
    lfw_action_t new_default_action = LFW_ACTION_DROP;

    lfw_status_t st = lfw_config_load_file(
        engine->config_path,
        &new_default_action,
        &new_rules,
        &new_rule_count
    );

    if (st != LFW_OK) {
        return st;
    }

    pthread_rwlock_wrlock(&engine->rules_lock);

    if (engine->ruleset.rules) {
        lfw_config_free_rules((lfw_rule_t *)engine->ruleset.rules);
    }

    engine->ruleset.rules = new_rules;
    engine->ruleset.rule_count = new_rule_count;
    engine->config.default_action = new_default_action;

    pthread_rwlock_unlock(&engine->rules_lock);

    return LFW_OK;
}

static void format_rule(const lfw_rule_t *rule, char *buf, size_t buf_len)
{
    int offset = 0;
    offset += snprintf(buf + offset, buf_len - offset, "%s",
                       rule->action == LFW_ACTION_ACCEPT ? "allow" : "deny");

    const char *proto = "any";
    if (rule->match.protocol == LFW_PROTO_TCP) proto = "tcp";
    else if (rule->match.protocol == LFW_PROTO_UDP) proto = "udp";
    else if (rule->match.protocol == LFW_PROTO_ICMP) proto = "icmp";

    if (rule->match.protocol != LFW_PROTO_ANY) {
        offset += snprintf(buf + offset, buf_len - offset, " %s", proto);
    }

    if (rule->match.match_dst_port) {
        offset += snprintf(buf + offset, buf_len - offset, " %u", ntohs(rule->match.dst_port.port));
    }

    if (rule->match.match_src_ip) {
        char ip_str[32];
        struct in_addr in;
        in.s_addr = rule->match.src_ip.addr;
        inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));

        lfw_u32 mask = ntohl(rule->match.src_mask.addr);
        int prefix = 0;
        for (int b = 31; b >= 0; b--) {
            if ((mask >> b) & 1) prefix++;
            else break;
        }

        if (prefix == 32) {
            offset += snprintf(buf + offset, buf_len - offset, " from %s", ip_str);
        } else {
            offset += snprintf(buf + offset, buf_len - offset, " from %s/%d", ip_str, prefix);
        }
    } else {
        offset += snprintf(buf + offset, buf_len - offset, " from any");
    }

    if (rule->match.match_dst_ip) {
        char ip_str[32];
        struct in_addr in;
        in.s_addr = rule->match.dst_ip.addr;
        inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));

        lfw_u32 mask = ntohl(rule->match.dst_mask.addr);
        int prefix = 0;
        for (int b = 31; b >= 0; b--) {
            if ((mask >> b) & 1) prefix++;
            else break;
        }

        if (prefix == 32) {
            offset += snprintf(buf + offset, buf_len - offset, " to %s", ip_str);
        } else {
            offset += snprintf(buf + offset, buf_len - offset, " to %s/%d", ip_str, prefix);
        }
    } else {
        offset += snprintf(buf + offset, buf_len - offset, " to any");
    }
}

void lfw_engine_dump_stats(const lfw_engine_t *engine)
{
    if (!engine)
        return;

    pthread_rwlock_t *lock = (pthread_rwlock_t *)&engine->rules_lock;
    pthread_rwlock_rdlock(lock);

    lfw_u32 conn_count = engine->connection_state ? lfw_state_get_count(engine->connection_state) : 0;

    lfw_log_info("=== Firewall Statistics ===");
    lfw_log_info("Active Connections Table Count: %u", conn_count);
    lfw_log_info("Default Policy Verdict: %s",
           engine->config.default_action == LFW_ACTION_ACCEPT ? "ACCEPT" : "DROP");
    lfw_log_info("Installed Rules Count: %u", engine->ruleset.rule_count);

    for (lfw_u32 i = 0; i < engine->ruleset.rule_count; i++) {
        const lfw_rule_t *rule = &engine->ruleset.rules[i];
        char rule_str[256];
        format_rule(rule, rule_str, sizeof(rule_str));
        lfw_log_info("  Rule #%u [%s]: hits=%lu, bytes=%lu",
               i + 1, rule_str, (unsigned long)rule->hit_count, (unsigned long)rule->byte_count);
    }

    lfw_log_info("===========================");

    pthread_rwlock_unlock(lock);
}
