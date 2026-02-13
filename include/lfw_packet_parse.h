#ifndef LFW_PACKET_PARSE_H
#define LFW_PACKET_PARSE_H

/*
 * lfw - Linux Firewall
 * Packet parsing interface
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "lfw_packet.h"
#include "lfw_types.h"

/*
 * Parse raw packet bytes into lfw_packet_t
 *
 * Returns:
 *   LFW_OK on success
 *   LFW_ERR_INVALID on malformed packet
 */
lfw_status_t lfw_parse_ipv4_packet(const uint8_t *data, size_t len, lfw_direction_t direction, lfw_packet_t *out_packet);

#endif /* LFW_PACKET_PARSE_H */
