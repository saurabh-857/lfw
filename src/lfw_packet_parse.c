#include "lfw_packet_parse.h"

/*
 * IPv4 header minimum size
 */
#define IPV4_MIN_HEADER_LEN 20

/*
 * Parse IPv4 packet safely
 */
lfw_status_t lfw_parse_ipv4_packet(const uint8_t *data, size_t len, lfw_direction_t direction, lfw_packet_t *out)
{
    uint8_t version_ihl;
    uint8_t ihl;
    uint8_t protocol;
    size_t ip_header_len;

    if (!data || !out) {
        return LFW_ERR_INVALID;
    }

    if (len < IPV4_MIN_HEADER_LEN) {
        return LFW_ERR_INVALID;
    }

    /* Version + IHL */
    version_ihl = data[0];
    if ((version_ihl >> 4) != 4) {
        return LFW_ERR_INVALID;
    }

    ihl = (version_ihl & 0x0F);
    ip_header_len = ihl * 4;

    if (ip_header_len < IPV4_MIN_HEADER_LEN || ip_header_len > len) {
        return LFW_ERR_INVALID;
    }

    /* Protocol */
    protocol = data[9];

    /* Clear output */
    *out = (lfw_packet_t){0};

    out->direction = direction;

    switch (protocol) {
        case 6:
            out->protocol = LFW_PROTO_TCP;
            break;
        case 17:
            out->protocol = LFW_PROTO_UDP;
            break;
        case 1:
            out->protocol = LFW_PROTO_ICMP;
            break;
        default:
            out->protocol = LFW_PROTO_ANY;
            break;
    }

    /* Source IP */
    out->ip4.src.addr =
        ((lfw_u32)data[12] << 24) |
        ((lfw_u32)data[13] << 16) |
        ((lfw_u32)data[14] << 8)  |
        ((lfw_u32)data[15]);

    /* Destination IP */
    out->ip4.dst.addr =
        ((lfw_u32)data[16] << 24) |
        ((lfw_u32)data[17] << 16) |
        ((lfw_u32)data[18] << 8)  |
        ((lfw_u32)data[19]);

    /* Transport layer (TCP/UDP only) */
    if (out->protocol == LFW_PROTO_TCP || out->protocol == LFW_PROTO_UDP) {

        if (len < ip_header_len + 4) {
            return LFW_ERR_INVALID;
        }

        out->l4.src_port.port =
            ((lfw_u16)data[ip_header_len] << 8) |
            ((lfw_u16)data[ip_header_len + 1]);

        out->l4.dst_port.port =
            ((lfw_u16)data[ip_header_len + 2] << 8) |
            ((lfw_u16)data[ip_header_len + 3]);
    }

    return LFW_OK;
}
