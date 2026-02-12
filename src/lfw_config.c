/*
 * lfw - Linux Firewall
 * Configuration file loader implementation
 */

#include "lfw_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* for strcasecmp, strtok_r on some libcs */

/* ------------------------------
 * Helpers
 * ------------------------------ */

static void lfw_trim_leading(char **p)
{
    while (**p && isspace((unsigned char)**p)) {
        (*p)++;
    }
}

static void lfw_init_rule(lfw_rule_t *rule, lfw_action_t action)
{
    memset(rule, 0, sizeof(*rule));
    rule->action = action;
    rule->match.protocol = LFW_PROTO_ANY; /* default: any protocol */
}

static int lfw_parse_ipv4(const char *text, lfw_ipv4_t *out)
{
    struct in_addr addr;

    if (!text || !out) {
        return 0;
    }

    if (inet_pton(AF_INET, text, &addr) != 1) {
        return 0;
    }

    out->addr = addr.s_addr; /* already in network byte order */
    return 1;
}

/*
 * Parse a port specification.
 *
 * Supported formats:
 *   "22"        → port 22, protocol unchanged
 *   "22/tcp"    → port 22, protocol forced to TCP
 *   "53/udp"    → port 53, protocol forced to UDP
 */
static int lfw_parse_port_and_proto(const char *text,
                                    lfw_proto_t *proto_inout,
                                    lfw_port_t *port_out,
                                    bool *match_port_out)
{
    char buf[32];
    char *slash;
    char *endptr;
    long port;
    lfw_proto_t proto = *proto_inout;

    if (!text || !proto_inout || !port_out || !match_port_out) {
        return 0;
    }

    if (strlen(text) >= sizeof(buf)) {
        return 0;
    }

    strcpy(buf, text);
    slash = strchr(buf, '/');

    if (slash) {
        *slash = '\0';
        slash++;

        if (strcasecmp(slash, "tcp") == 0) {
            proto = LFW_PROTO_TCP;
        } else if (strcasecmp(slash, "udp") == 0) {
            proto = LFW_PROTO_UDP;
        } else if (strcasecmp(slash, "icmp") == 0) {
            proto = LFW_PROTO_ICMP;
        } else {
            return 0; /* unknown protocol suffix */
        }
    }

    port = strtol(buf, &endptr, 10);
    if (*endptr != '\0' || port <= 0 || port > 65535) {
        return 0;
    }

    port_out->port = htons((lfw_u16)port);
    *match_port_out = true;
    *proto_inout = proto;
    return 1;
}

/*
 * Parse one config line into a rule.
 *
 * Returns:
 *   1 on success and fills *out_rule
 *   0 if the line is invalid or should be ignored
 */
static int lfw_parse_rule_line(char *line, lfw_rule_t *out_rule)
{
    char *tok;
    lfw_action_t action;
    lfw_rule_t rule;
    int have_proto_or_port = 0;

    if (!line || !out_rule) {
        return 0;
    }

    lfw_trim_leading(&line);
    if (*line == '\0' || *line == '#') {
        return 0; /* empty or comment */
    }

    tok = strtok(line, " \t\r\n");
    if (!tok) {
        return 0;
    }

    if (strcasecmp(tok, "allow") == 0) {
        action = LFW_ACTION_ACCEPT;
    } else if (strcasecmp(tok, "deny") == 0 || strcasecmp(tok, "drop") == 0) {
        action = LFW_ACTION_DROP;
    } else {
        /* unsupported keyword (e.g. "default" or garbage) */
        return 0;
    }

    lfw_init_rule(&rule, action);

    /* Optional: protocol / port / "any" */
    tok = strtok(NULL, " \t\r\n");
    if (tok) {
        if (strcasecmp(tok, "any") == 0) {
            /* anything, leave protocol as ANY */
            have_proto_or_port = 1;
        } else if (strcasecmp(tok, "tcp") == 0) {
            rule.match.protocol = LFW_PROTO_TCP;
            have_proto_or_port = 1;
        } else if (strcasecmp(tok, "udp") == 0) {
            rule.match.protocol = LFW_PROTO_UDP;
            have_proto_or_port = 1;
        } else if (strcasecmp(tok, "icmp") == 0) {
            rule.match.protocol = LFW_PROTO_ICMP;
            have_proto_or_port = 1;
        } else {
            /*
             * If it is not recognized as a protocol keyword,
             * treat it as a port specification.
             */
            if (!lfw_parse_port_and_proto(tok,
                                          &rule.match.protocol,
                                          &rule.match.dst_port,
                                          &rule.match.match_dst_port)) {
                return 0;
            }
            have_proto_or_port = 1;
        }
    }

    /*
     * If we only saw a protocol token, check if the next token is
     * a port number.
     */
    if (have_proto_or_port && !rule.match.match_dst_port) {
        char *next = strtok(NULL, " \t\r\n");
        if (next && strcasecmp(next, "from") != 0 && strcasecmp(next, "to") != 0) {
            /* Try parsing as port; if it fails, push the token back logically
             * by rewinding saveptr is complicated, so we simply treat failure
             * as "no port" and continue parsing any "from/to" that may follow.
             */
            (void)lfw_parse_port_and_proto(next,
                                           &rule.match.protocol,
                                           &rule.match.dst_port,
                                           &rule.match.match_dst_port);
        } else if (next) {
            /* next is "from"/"to" → process it below */
            tok = next;
        }
    }

    /*
     * Optional: "from SRC" / "to DST"
     */
    while ((tok = tok ? tok : strtok(NULL, " \t\r\n"))) {
        if (strcasecmp(tok, "from") == 0) {
            char *ip = strtok(NULL, " \t\r\n");
            if (!ip || strcasecmp(ip, "any") == 0) {
                /* nothing to do */
                tok = NULL;
                continue;
            }

            if (!lfw_parse_ipv4(ip, &rule.match.src_ip)) {
                return 0;
            }
            rule.match.match_src_ip = true;
            tok = NULL;
        } else if (strcasecmp(tok, "to") == 0) {
            char *ip = strtok(NULL, " \t\r\n");
            if (!ip || strcasecmp(ip, "any") == 0) {
                tok = NULL;
                continue;
            }

            if (!lfw_parse_ipv4(ip, &rule.match.dst_ip)) {
                return 0;
            }
            rule.match.match_dst_ip = true;
            tok = NULL;
        } else {
            /* Unexpected token; stop parsing this line */
            break;
        }
    }

    *out_rule = rule;
    return 1;
}

/* ------------------------------
 * Public API
 * ------------------------------ */

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

    if (!path || !default_action || !rules_out || !rule_count_out) {
        return LFW_ERR_INVALID;
    }

    fp = fopen(path, "r");
    if (!fp) {
        return LFW_ERR_INVALID;
    }

    /* Default policy if not overridden in file.
     * Currently we do not parse an explicit "default" keyword,
     * but this can be extended later.
     */
    *default_action = LFW_ACTION_ACCEPT;

    while (fgets(line, sizeof(line), fp)) {
        lfw_rule_t rule;

        if (!lfw_parse_rule_line(line, &rule)) {
            continue; /* ignore invalid / comment / empty lines */
        }

        if (count == capacity) {
            lfw_u32 new_capacity = (capacity == 0) ? 8u : capacity * 2u;
            lfw_rule_t *new_rules = realloc(rules, new_capacity * sizeof(*new_rules));

            if (!new_rules) {
                fclose(fp);
                free(rules);
                return LFW_ERR_NO_MEMORY;
            }

            rules = new_rules;
            capacity = new_capacity;
        }

        rules[count++] = rule;
    }

    fclose(fp);

    if (count == 0) {
        free(rules);
        return LFW_ERR_INVALID;
    }

    *rules_out = rules;
    *rule_count_out = count;
    return LFW_OK;
}

void lfw_config_free_rules(lfw_rule_t *rules)
{
    free(rules);
}

