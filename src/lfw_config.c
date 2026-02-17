#include "lfw_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// ------------------------------
// Helpers
// ------------------------------

static void trim_leading(char **p)
{
    while (**p && isspace((unsigned char)**p))
        (*p)++;
}

static void init_rule(lfw_rule_t *rule, lfw_action_t action)
{
    memset(rule, 0, sizeof(*rule));
    rule->action = action;
    rule->match.protocol = LFW_PROTO_ANY;
}

static bool parse_ipv4(const char *text, lfw_ipv4_t *out)
{
    struct in_addr addr;

    if (!text || !out)
        return false;

    if (inet_pton(AF_INET, text, &addr) != 1)
        return false;

    out->addr = addr.s_addr;
    return true;
}

static bool parse_port_proto(const char *text,
                             lfw_proto_t *proto_inout,
                             lfw_port_t *port_out,
                             bool *match_port_out)
{
    char buf[32];
    char *slash;
    char *endptr;
    long port;

    if (!text || !proto_inout || !port_out || !match_port_out)
        return false;

    if (strlen(text) >= sizeof(buf))
        return false;

    strcpy(buf, text);
    slash = strchr(buf, '/');

    if (slash) {
        *slash = '\0';
        slash++;

        if (strcasecmp(slash, "tcp") == 0)
            *proto_inout = LFW_PROTO_TCP;
        else if (strcasecmp(slash, "udp") == 0)
            *proto_inout = LFW_PROTO_UDP;
        else if (strcasecmp(slash, "icmp") == 0)
            *proto_inout = LFW_PROTO_ICMP;
        else
            return false;
    }

    port = strtol(buf, &endptr, 10);
    if (*endptr != '\0' || port <= 0 || port > 65535)
        return false;

    port_out->port = htons((lfw_u16)port);
    *match_port_out = true;

    return true;
}

// ------------------------------
// Parse single rule line
// ------------------------------

static lfw_status_t parse_rule_line(char *line,
                                    lfw_action_t *default_action,
                                    lfw_rule_t *out_rule,
                                    bool *is_rule)
{
    char *tok;

    *is_rule = false;

    trim_leading(&line);

    if (*line == '\0' || *line == '#')
        return LFW_OK;

    tok = strtok(line, " \t\r\n");
    if (!tok)
        return LFW_OK;

    // Handle default policy
    if (strcasecmp(tok, "default") == 0) {
        char *policy = strtok(NULL, " \t\r\n");
        if (!policy)
            return LFW_ERR_INVALID;

        if (strcasecmp(policy, "allow") == 0)
            *default_action = LFW_ACTION_ACCEPT;
        else if (strcasecmp(policy, "deny") == 0)
            *default_action = LFW_ACTION_DROP;
        else
            return LFW_ERR_INVALID;

        return LFW_OK;
    }

    // Rule must start with allow or deny
    lfw_action_t action;

    if (strcasecmp(tok, "allow") == 0)
        action = LFW_ACTION_ACCEPT;
    else if (strcasecmp(tok, "deny") == 0 ||
             strcasecmp(tok, "drop") == 0)
        action = LFW_ACTION_DROP;
    else
        return LFW_ERR_INVALID;

    lfw_rule_t rule;
    init_rule(&rule, action);

    tok = strtok(NULL, " \t\r\n");

    // Optional protocol
    if (tok) {

        if (strcasecmp(tok, "tcp") == 0) {
            rule.match.protocol = LFW_PROTO_TCP;
            tok = strtok(NULL, " \t\r\n");
        }
        else if (strcasecmp(tok, "udp") == 0) {
            rule.match.protocol = LFW_PROTO_UDP;
            tok = strtok(NULL, " \t\r\n");
        }
        else if (strcasecmp(tok, "icmp") == 0) {
            rule.match.protocol = LFW_PROTO_ICMP;
            tok = strtok(NULL, " \t\r\n");
        }
        else if (strcasecmp(tok, "any") == 0) {
            tok = strtok(NULL, " \t\r\n");
        }
    }

    // Optional port (after protocol or directly after action)
    if (tok &&
        strcasecmp(tok, "from") != 0 &&
        strcasecmp(tok, "to") != 0)
    {
        if (parse_port_proto(tok,
                            &rule.match.protocol,
                            &rule.match.dst_port,
                            &rule.match.match_dst_port))
        {
            tok = strtok(NULL, " \t\r\n");
        }
        else
        {
            return LFW_ERR_INVALID;
        }
    }


    // Optional from/to
    while (tok) {

        if (strcasecmp(tok, "from") == 0) {
            char *ip = strtok(NULL, " \t\r\n");
            if (!ip)
                return LFW_ERR_INVALID;

            if (strcasecmp(ip, "any") != 0) {
                if (!parse_ipv4(ip, &rule.match.src_ip))
                    return LFW_ERR_INVALID;

                rule.match.match_src_ip = true;
            }
        }
        else if (strcasecmp(tok, "to") == 0) {
            char *ip = strtok(NULL, " \t\r\n");
            if (!ip)
                return LFW_ERR_INVALID;

            if (strcasecmp(ip, "any") != 0) {
                if (!parse_ipv4(ip, &rule.match.dst_ip))
                    return LFW_ERR_INVALID;

                rule.match.match_dst_ip = true;
            }
        }
        else {
            return LFW_ERR_INVALID;
        }

        tok = strtok(NULL, " \t\r\n");
    }

    *out_rule = rule;
    *is_rule = true;

    return LFW_OK;
}

// ------------------------------
// Public API
// ------------------------------

lfw_status_t lfw_config_load_file(const char *path,
                                lfw_action_t *default_action,
                                lfw_rule_t **rules_out,
                                lfw_u32 *rule_count_out)
{
    FILE *fp;
    char line[256];
    lfw_rule_t *rules = NULL;
    lfw_u32 count = 0;
    lfw_u32 capacity = 0;
    unsigned int line_no = 0;

    if (!path || !default_action ||
        !rules_out || !rule_count_out)
        return LFW_ERR_INVALID;

    fp = fopen(path, "r");
    if (!fp)
        return LFW_ERR_INVALID;

    *default_action = LFW_ACTION_DROP;

    while (fgets(line, sizeof(line), fp)) {

        line_no++;

        lfw_rule_t rule;
        bool is_rule = false;

        lfw_status_t st = parse_rule_line(
            line,
            default_action,
            &rule,
            &is_rule
        );

        if (st != LFW_OK) {
            fprintf(stderr,
                    "[lfw] config error at line %u\n",
                    line_no);
            fclose(fp);
            free(rules);
            return LFW_ERR_INVALID;
        }

        if (!is_rule)
            continue;

        if (count == capacity) {
            lfw_u32 new_cap = capacity ? capacity * 2 : 8;
            lfw_rule_t *tmp =
                realloc(rules, new_cap * sizeof(*tmp));

            if (!tmp) {
                fclose(fp);
                free(rules);
                return LFW_ERR_NO_MEMORY;
            }

            rules = tmp;
            capacity = new_cap;
        }

        rules[count++] = rule;
    }

    fclose(fp);

    *rules_out = rules;
    *rule_count_out = count;

    return LFW_OK;
}

void lfw_config_free_rules(lfw_rule_t *rules)
{
    free(rules);
}
