/*
 * lfw - Linux Firewall
 * Configuration file loader
 *
 * This module is responsible for parsing a simple, ufw‑like
 * rule language from a text file and converting it into the
 * internal rule representation used by the engine.
 *
 * Rule syntax (one rule per line):
 *
 *   ACTION [PROTO] [PORT] [from SRC] [to DST]
 *
 * Where:
 *   ACTION  : "allow" | "deny" (maps to ACCEPT / DROP)
 *   PROTO   : "any" | "tcp" | "udp" | "icmp"   (optional, default: any)
 *   PORT    : integer port (e.g. "22"), or "PORT/PROTO" (e.g. "22/tcp")
 *             (optional; when present, matches destination port)
 *   SRC/DST : "any" or IPv4 address (e.g. "192.168.1.10")
 *
 * Examples:
 *   allow tcp 80
 *   deny tcp 22
 *   allow udp 53 from 192.168.1.53
 *   deny any
 *
 * Lines starting with '#' or empty lines are ignored.
 */

#ifndef LFW_CONFIG_H
#define LFW_CONFIG_H

#include "lfw_rules.h"
#include "lfw_types.h"

/*
 * Load rules from a configuration file.
 *
 * Parameters:
 *   path           : path to the rules file
 *   default_action : out param, default policy (e.g. ACCEPT)
 *   rules_out      : out param, pointer to dynamically allocated rule array
 *   rule_count_out : out param, number of rules in the array
 *
 * Returns:
 *   LFW_OK on success, error code otherwise.
 *
 * Notes:
 *   - On success, *rules_out points to heap memory that must be
 *     freed by the caller (via lfw_config_free_rules()).
 *   - On failure, *rules_out and *rule_count_out are left untouched.
 */
lfw_status_t lfw_config_load_file(const char *path,
                                  lfw_action_t *default_action,
                                  lfw_rule_t **rules_out,
                                  lfw_u32 *rule_count_out);

/*
 * Free rules previously allocated by lfw_config_load_file().
 */
void lfw_config_free_rules(lfw_rule_t *rules);

#endif /* LFW_CONFIG_H */

