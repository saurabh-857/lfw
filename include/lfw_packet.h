#ifndef LFW_PACKET_H
#define LFW_PACKET_H

#include <stdbool.h>
#include "lfw_types.h"

// IPv4 header abstraction
typedef struct {
    lfw_ipv4_t src;
    lfw_ipv4_t dst;
} lfw_ip4_hdr_t;

// Transport ports
typedef struct {
    lfw_port_t src_port;
    lfw_port_t dst_port;
} lfw_l4_ports_t;

// Normalized firewall packet
typedef struct {
    lfw_direction_t direction;
    lfw_proto_t     protocol;

    lfw_ip4_hdr_t   ip4;
    lfw_l4_ports_t  l4;

    bool is_new_connection;
} lfw_packet_t;

#endif
