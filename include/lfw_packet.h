#ifndef LFW_PACKET_H
#define LFW_PACKET_H

/*
 * lfw - Linux Firewall
 * Normalized packet abstraction
 *
 * This represents a decoded network packet
 * as seen by the firewall engine.
 */

#include <stdbool.h>
#include "lfw_types.h"

/* ==============================
 * Layer 3 (IP)
 * ============================== */
typedef struct {
    lfw_ipv4_t src;
    lfw_ipv4_t dst;
} lfw_ip4_hdr_t;

/* ==============================
 * Layer 4 (Transport)
 * ============================== */
typedef struct {
    lfw_port_t src_port;
    lfw_port_t dst_port;
} lfw_l4_ports_t;

/* ==============================
 * Normalized packet
 * ============================== */
typedef struct {
    /* Metadata */
    lfw_direction_t direction;
    lfw_proto_t     protocol;

    /* Layer 3 */
    lfw_ip4_hdr_t   ip4;

    /* Layer 4 */
    lfw_l4_ports_t  l4;

    /*
     * Connection semantics (for stateful firewall).
     * true = first packet of a connection (e.g. TCP SYN, or any UDP).
     * Used so we only apply allow/deny rules to new connections;
     * established traffic is allowed by connection table.
     */
    bool is_new_connection;

} lfw_packet_t;

#endif /* LFW_PACKET_H */
