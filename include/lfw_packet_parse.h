#ifndef LFW_PACKET_PARSE_H
#define LFW_PACKET_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "lfw_packet.h"
#include "lfw_types.h"

// Parse IPv4 packet
lfw_status_t lfw_parse_ipv4_packet(
    const uint8_t *data,
    size_t len,
    lfw_direction_t direction,
    lfw_packet_t *out_packet
);

#endif
