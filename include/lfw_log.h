// SPDX-License-Identifier: GPL-3.0-only

#ifndef LFW_LOG_H
#define LFW_LOG_H

#include "lfw_types.h"
#include "lfw_packet.h"

// Log target configuration
typedef enum {
    LFW_LOG_CONSOLE = 0,
    LFW_LOG_SYSLOG
} lfw_log_target_t;

// Initialize the logging subsystem
void lfw_log_init(lfw_log_target_t target);

// Close the logging subsystem
void lfw_log_close(void);

// Log raw packet verdict decisions
void lfw_log_packet(const lfw_packet_t *pkt, lfw_verdict_t verdict);

// General info and error logs
void lfw_log_info(const char *fmt, ...);
void lfw_log_error(const char *fmt, ...);
void lfw_log_debug(const char *fmt, ...);

// Log level configuration
void lfw_log_set_level(lfw_loglevel_t level);
lfw_loglevel_t lfw_log_get_level(void);

#endif
