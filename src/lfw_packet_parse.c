#include "lfw_packet_parse.h"

#define IPV4_MIN_HEADER_LEN 20

lfw_status_t lfw_parse_ipv4_packet(const uint8_t *data,
                                    size_t len,
                                    lfw_direction_t direction,
                                    lfw_packet_t *out_packet)
{
    if (!data || !out_packet)
        return LFW_ERR_INVALID;

    if (len < IPV4_MIN_HEADER_LEN)
        return LFW_ERR_INVALID;

    uint8_t version_ihl = data[0];
    uint8_t version = version_ihl >> 4;
    uint8_t ihl = version_ihl & 0x0F;

    if (version != 4)
        return LFW_ERR_INVALID;

    size_t ip_header_len = ihl * 4;

    if (ip_header_len < IPV4_MIN_HEADER_LEN ||
        ip_header_len > len)
        return LFW_ERR_INVALID;

    memset(out_packet, 0, sizeof(*out_packet));

    out_packet->direction = direction;

    uint8_t proto = data[9];

    if (proto == 6)
        out_packet->protocol = LFW_PROTO_TCP;
    else if (proto == 17)
        out_packet->protocol = LFW_PROTO_UDP;
    else if (proto == 1)
        out_packet->protocol = LFW_PROTO_ICMP;
    else
        out_packet->protocol = LFW_PROTO_ANY;

    memcpy(&out_packet->ip4.src.addr, &data[12], sizeof(lfw_u32));
    memcpy(&out_packet->ip4.dst.addr, &data[16], sizeof(lfw_u32));

    // Only TCP/UDP have ports
    if (out_packet->protocol == LFW_PROTO_TCP ||
        out_packet->protocol == LFW_PROTO_UDP)
    {
        if (len < ip_header_len + 4)
            return LFW_ERR_INVALID;

        // Replace the port assignment lines with:
        out_packet->l4.src_port.port = htons(((lfw_u16)data[ip_header_len] << 8) |
                                            ((lfw_u16)data[ip_header_len + 1]));

        out_packet->l4.dst_port.port = htons(((lfw_u16)data[ip_header_len + 2] << 8) |
                                            ((lfw_u16)data[ip_header_len + 3]));

        // Determine new connection
        if (out_packet->protocol == LFW_PROTO_TCP) {

            if (len < ip_header_len + 14)
                return LFW_ERR_INVALID;

            uint8_t tcp_flags = data[ip_header_len + 13];

            bool syn = (tcp_flags & 0x02) != 0;
            bool ack = (tcp_flags & 0x10) != 0;

            out_packet->is_new_connection = syn && !ack;
        }
        else {
            // UDP treated as connection-based with timeout
            out_packet->is_new_connection = true;
        }
    }
    else {
        out_packet->is_new_connection = false;
    }

    return LFW_OK;
}
