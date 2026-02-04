#include <string.h>
#include "test_utils.h"
#include "lfw_packet_parse.h"

static void test_valid_tcp_packet(void)
{
    /* Minimal IPv4 + TCP header */
    uint8_t pkt[] = {
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 10,
        192, 168, 1, 1,
        0x00, 0x50,         // src port 80
        0x01, 0xbb          // dst port 443
    };

    lfw_packet_t p;
    lfw_status_t rc;

    rc = lfw_parse_ipv4_packet(pkt, sizeof(pkt), LFW_DIR_INBOUND, &p);

    TEST_ASSERT(rc == LFW_OK, "valid packet rejected");
    TEST_ASSERT(p.protocol == LFW_PROTO_TCP, "wrong protocol");
    TEST_ASSERT(p.ip4.src.addr != 0, "src ip missing");
    TEST_ASSERT(p.l4.dst_port.port == 443, "dst port mismatch");

    TEST_PASS("valid TCP packet parsed");
}

static void test_truncated_packet(void)
{
    uint8_t pkt[10] = {0};

    lfw_packet_t p;
    lfw_status_t rc;

    rc = lfw_parse_ipv4_packet(pkt, sizeof(pkt), LFW_DIR_INBOUND, &p);

    TEST_ASSERT(rc != LFW_OK, "truncated packet accepted");
    TEST_PASS("truncated packet rejected");
}

void run_packet_parse_tests(void)
{
    test_valid_tcp_packet();
    test_truncated_packet();
}
