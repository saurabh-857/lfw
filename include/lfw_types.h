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
    LFW_PROTO_TCP,
    LFW_PROTO_UDP,
    LFW_PROTO_ICMP
} lfw_proto_t;

// IPv4 address (network byte order)
typedef struct {
    lfw_u32 addr;
} lfw_ipv4_t;

// Port (network byte order)
typedef struct {
    lfw_u16 port;
} lfw_port_t;

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

#endif
