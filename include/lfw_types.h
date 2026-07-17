// SPDX-License-Identifier: GPL-3.0-only

#ifndef LFW_TYPES_H
#define LFW_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Fixed-width types
typedef uint8_t  lfw_u8;
typedef uint16_t lfw_u16;
typedef uint32_t lfw_u32;
typedef uint64_t lfw_u64;

// Firewall verdict
typedef enum {
    LFW_VERDICT_UNDECIDED = 0,
    LFW_VERDICT_ACCEPT,
    LFW_VERDICT_DROP
} lfw_verdict_t;

// L4 protocol
typedef enum {
    LFW_PROTO_ANY = 0,
    LFW_PROTO_ICMP = 1,
    LFW_PROTO_IGMP = 2,
    LFW_PROTO_TCP = 6,
    LFW_PROTO_UDP = 17,
    LFW_PROTO_ESP = 50,
    LFW_PROTO_AH = 51,
    LFW_PROTO_ICMPV6 = 58
} lfw_proto_t;


// IPv4 address (network byte order)
typedef struct {
    lfw_u32 addr;
} lfw_ipv4_t;

// IPv6 address
typedef struct {
    lfw_u8 addr[16];
} lfw_ipv6_t;

// Unified IP address
typedef struct {
    lfw_u8 ip_version; // 4 or 6
    union {
        lfw_ipv4_t v4;
        lfw_ipv6_t v6;
    };
} lfw_ip_t;

// Port (network byte order)
typedef struct {
    lfw_u16 port;
} lfw_port_t;

// Port range (host byte order)
typedef struct {
    lfw_u16 min;
    lfw_u16 max;
} lfw_port_range_t;

// Packet direction
typedef enum {
    LFW_DIR_UNKNOWN = 0,
    LFW_DIR_INBOUND,
    LFW_DIR_OUTBOUND
} lfw_direction_t;

// Return status
typedef enum {
    LFW_OK = 0,
    LFW_ERR_GENERIC = -1,
    LFW_ERR_NO_MEMORY = -2,
    LFW_ERR_INVALID = -3,
    LFW_ERR_NOT_SUPPORTED = -4
} lfw_status_t;

// Log level
typedef enum {
    LFW_LOG_MINIMAL = 0,
    LFW_LOG_OPTIMAL = 1,
    LFW_LOG_MAX = 2,
    LFW_LOG_SUPER_MAX = 3
} lfw_loglevel_t;

#endif
