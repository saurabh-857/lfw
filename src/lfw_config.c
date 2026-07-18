// SPDX-License-Identifier: GPL-3.0-only

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

static bool is_valid_fqdn(const char *str)
{
    if (!str || *str == '\0')
        return false;
    for (int i = 0; str[i] != '\0'; i++) {
        char c = str[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '-')
            return false;
    }
    return true;
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

static bool parse_ipv4_cidr(const char *text, lfw_ipv4_t *ip_out, lfw_ipv4_t *mask_out)
{
    if (!text || !ip_out || !mask_out)
        return false;

    char buf[64];
    if (strlen(text) >= sizeof(buf))
        return false;
    strcpy(buf, text);

    char *slash = strchr(buf, '/');
    if (!slash) {
        if (!parse_ipv4(buf, ip_out))
            return false;
        mask_out->addr = 0xFFFFFFFFu;
        return true;
    }

    *slash = '\0';
    char *cidr_str = slash + 1;

    if (!parse_ipv4(buf, ip_out))
        return false;

    char *endptr;
    long prefix = strtol(cidr_str, &endptr, 10);
    if (*endptr != '\0' || prefix < 0 || prefix > 32)
        return false;

    lfw_u32 mask_val = (prefix == 0) ? 0 : (~0u << (32 - prefix));
    mask_out->addr = htonl(mask_val);

    ip_out->addr &= mask_out->addr;
    return true;
}

static bool parse_ipv6(const char *text, lfw_ipv6_t *out)
{
    struct in6_addr addr;

    if (!text || !out)
        return false;

    if (inet_pton(AF_INET6, text, &addr) != 1)
        return false;

    memcpy(out->addr, addr.s6_addr, 16);
    return true;
}

static bool parse_ipv6_cidr(const char *text, lfw_ipv6_t *ip_out, lfw_ipv6_t *mask_out)
{
    if (!text || !ip_out || !mask_out)
        return false;

    char buf[128];
    if (strlen(text) >= sizeof(buf))
        return false;
    strcpy(buf, text);

    char *slash = strchr(buf, '/');
    if (!slash) {
        if (!parse_ipv6(buf, ip_out))
            return false;
        memset(mask_out->addr, 0xFF, 16);
        return true;
    }

    *slash = '\0';
    char *cidr_str = slash + 1;

    if (!parse_ipv6(buf, ip_out))
        return false;

    char *endptr;
    long prefix = strtol(cidr_str, &endptr, 10);
    if (*endptr != '\0' || prefix < 0 || prefix > 128)
        return false;

    memset(mask_out->addr, 0, 16);
    for (int i = 0; i < 16; i++) {
        if (prefix >= 8) {
            mask_out->addr[i] = 0xFF;
            prefix -= 8;
        } else if (prefix > 0) {
            mask_out->addr[i] = (uint8_t)(0xFF << (8 - prefix));
            prefix = 0;
        } else {
            mask_out->addr[i] = 0;
        }
    }

    for (int i = 0; i < 16; i++) {
        ip_out->addr[i] &= mask_out->addr[i];
    }
    return true;
}

static bool parse_ip_cidr(const char *text, lfw_ip_t *ip_out, lfw_ip_t *mask_out)
{
    if (!text || !ip_out || !mask_out)
        return false;

    if (strchr(text, ':') != NULL) {
        ip_out->ip_version = 6;
        mask_out->ip_version = 6;
        return parse_ipv6_cidr(text, &ip_out->v6, &mask_out->v6);
    } else {
        ip_out->ip_version = 4;
        mask_out->ip_version = 4;
        return parse_ipv4_cidr(text, &ip_out->v4, &mask_out->v4);
    }
}

static bool parse_port_proto(const char *text,
                             lfw_proto_t *proto_inout,
                             lfw_port_range_t *port_range_out,
                             bool *match_port_out)
{
    char buf[32];
    char *slash;
    char *endptr;

    if (!text || !proto_inout || !port_range_out || !match_port_out)
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
        else if (strcasecmp(slash, "igmp") == 0)
            *proto_inout = LFW_PROTO_IGMP;
        else if (strcasecmp(slash, "icmpv6") == 0)
            *proto_inout = LFW_PROTO_ICMPV6;
        else if (strcasecmp(slash, "esp") == 0)
            *proto_inout = LFW_PROTO_ESP;
        else if (strcasecmp(slash, "ah") == 0)
            *proto_inout = LFW_PROTO_AH;
        else
            return false;
    }

    char *dash = strchr(buf, '-');
    if (dash) {
        *dash = '\0';
        char *min_str = buf;
        char *max_str = dash + 1;

        long p_min = strtol(min_str, &endptr, 10);
        if (*endptr != '\0' || p_min <= 0 || p_min > 65535)
            return false;

        long p_max = strtol(max_str, &endptr, 10);
        if (*endptr != '\0' || p_max <= 0 || p_max > 65535 || p_max < p_min)
            return false;

        port_range_out->min = (lfw_u16)p_min;
        port_range_out->max = (lfw_u16)p_max;
    } else {
        long port = strtol(buf, &endptr, 10);
        if (*endptr != '\0' || port <= 0 || port > 65535)
            return false;

        port_range_out->min = (lfw_u16)port;
        port_range_out->max = (lfw_u16)port;
    }

    *match_port_out = true;
    return true;
}

// ------------------------------
// Parse single rule line
// ------------------------------

static lfw_status_t parse_rule_line(char *line,
                                    lfw_action_t *default_action,
                                    lfw_loglevel_t *loglevel,
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

    // Handle loglevel keyword
    if (strcasecmp(tok, "loglevel") == 0) {
        char *level_str = strtok(NULL, " \t\r\n");
        if (!level_str)
            return LFW_ERR_INVALID;

        if (strcasecmp(level_str, "minimal") == 0)
            *loglevel = LFW_LOG_MINIMAL;
        else if (strcasecmp(level_str, "optimal") == 0)
            *loglevel = LFW_LOG_OPTIMAL;
        else if (strcasecmp(level_str, "max") == 0)
            *loglevel = LFW_LOG_MAX;
        else if (strcasecmp(level_str, "super_max") == 0)
            *loglevel = LFW_LOG_SUPER_MAX;
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
        else if (strcasecmp(tok, "igmp") == 0) {
            rule.match.protocol = LFW_PROTO_IGMP;
            tok = strtok(NULL, " \t\r\n");
        }
        else if (strcasecmp(tok, "icmpv6") == 0) {
            rule.match.protocol = LFW_PROTO_ICMPV6;
            tok = strtok(NULL, " \t\r\n");
        }
        else if (strcasecmp(tok, "esp") == 0) {
            rule.match.protocol = LFW_PROTO_ESP;
            tok = strtok(NULL, " \t\r\n");
        }
        else if (strcasecmp(tok, "ah") == 0) {
            rule.match.protocol = LFW_PROTO_AH;
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
                if (!parse_ip_cidr(ip, &rule.match.src_ip, &rule.match.src_mask)) {
                    if (is_valid_fqdn(ip) && strlen(ip) < sizeof(rule.match.src_fqdn)) {
                        strncpy(rule.match.src_fqdn, ip, sizeof(rule.match.src_fqdn) - 1);
                        rule.match.has_src_fqdn = true;
                    } else {
                        return LFW_ERR_INVALID;
                    }
                } else {
                    rule.match.match_src_ip = true;
                }
            }
        }
        else if (strcasecmp(tok, "to") == 0) {
            char *ip = strtok(NULL, " \t\r\n");
            if (!ip)
                return LFW_ERR_INVALID;

            if (strcasecmp(ip, "any") != 0) {
                if (!parse_ip_cidr(ip, &rule.match.dst_ip, &rule.match.dst_mask)) {
                    if (is_valid_fqdn(ip) && strlen(ip) < sizeof(rule.match.dst_fqdn)) {
                        strncpy(rule.match.dst_fqdn, ip, sizeof(rule.match.dst_fqdn) - 1);
                        rule.match.has_dst_fqdn = true;
                    } else {
                        return LFW_ERR_INVALID;
                    }
                } else {
                    rule.match.match_dst_ip = true;
                }
            }
        }
        else {
            return LFW_ERR_INVALID;
        }

        tok = strtok(NULL, " \t\r\n");
    }

    if (rule.match.match_src_ip && rule.match.match_dst_ip) {
        if (rule.match.src_ip.ip_version != rule.match.dst_ip.ip_version) {
            return LFW_ERR_INVALID;
        }
    }

    if (rule.match.match_src_ip) {
        rule.match.ip_version = rule.match.src_ip.ip_version;
    } else if (rule.match.match_dst_ip) {
        rule.match.ip_version = rule.match.dst_ip.ip_version;
    } else {
        rule.match.ip_version = 0; // any
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
                                  lfw_u32 *rule_count_out,
                                  lfw_loglevel_t *loglevel_out)
{
    FILE *fp;
    char line[256];
    lfw_rule_t *rules = NULL;
    lfw_u32 count = 0;
    lfw_u32 capacity = 0;
    unsigned int line_no = 0;

    if (!path || !default_action ||
        !rules_out || !rule_count_out || !loglevel_out)
        return LFW_ERR_INVALID;

    fp = fopen(path, "r");
    if (!fp)
        return LFW_ERR_INVALID;

    *default_action = LFW_ACTION_DROP;
    *loglevel_out = LFW_LOG_OPTIMAL;

    while (fgets(line, sizeof(line), fp)) {

        line_no++;

        lfw_rule_t rule;
        bool is_rule = false;

        lfw_status_t st = parse_rule_line(
            line,
            default_action,
            loglevel_out,
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
