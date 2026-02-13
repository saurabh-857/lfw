#include "lfw_state.h"
#include <stdlib.h>
#include <string.h>

/*
 * Fixed-size connection state table.
 * Key = (src_ip, dst_ip, src_port, dst_port, protocol).
 */
#define LFW_STATE_TABLE_SIZE  4096
#define LFW_STATE_EMPTY_MARK  0xFFFFFFFFu

typedef struct {
    lfw_u32    src_ip;
    lfw_u32    dst_ip;
    lfw_u16    src_port;
    lfw_u16    dst_port;
    lfw_u8     protocol;
    lfw_u8     _pad;
} lfw_conn_key_t;

struct lfw_state {
    lfw_conn_key_t *slots;
    lfw_u32         count;
    lfw_u32         cap;
};

static lfw_u32 hash_key(const lfw_conn_key_t *k)
{
    lfw_u32 h = k->src_ip ^ k->dst_ip;
    h ^= (lfw_u32)k->src_port << 16 | k->dst_port;
    h ^= (lfw_u32)k->protocol << 24;
    return h;
}

static void key_from_packet(const lfw_packet_t *pkt, lfw_conn_key_t *k)
{
    k->src_ip    = pkt->ip4.src.addr;
    k->dst_ip    = pkt->ip4.dst.addr;
    k->src_port  = pkt->l4.src_port.port;
    k->dst_port  = pkt->l4.dst_port.port;
    k->protocol  = (lfw_u8)pkt->protocol;
    k->_pad      = 0;
}

static bool key_equal(const lfw_conn_key_t *a, const lfw_conn_key_t *b)
{
    return a->src_ip == b->src_ip
        && a->dst_ip == b->dst_ip
        && a->src_port == b->src_port
        && a->dst_port == b->dst_port
        && a->protocol == b->protocol;
}

static bool key_is_empty(const lfw_conn_key_t *k)
{
    return k->src_ip == LFW_STATE_EMPTY_MARK && k->dst_ip == LFW_STATE_EMPTY_MARK;
}

static void key_set_empty(lfw_conn_key_t *k)
{
    k->src_ip   = LFW_STATE_EMPTY_MARK;
    k->dst_ip   = LFW_STATE_EMPTY_MARK;
    k->src_port = 0;
    k->dst_port = 0;
    k->protocol = 0;
}

lfw_state_t *lfw_state_create(void)
{
    lfw_state_t *s = (lfw_state_t *)malloc(sizeof(lfw_state_t));
    if (!s) {
        return NULL;
    }
    s->cap   = LFW_STATE_TABLE_SIZE;
    s->count = 0;
    s->slots = (lfw_conn_key_t *)calloc(s->cap, sizeof(lfw_conn_key_t));
    if (!s->slots) {
        free(s);
        return NULL;
    }
    for (lfw_u32 i = 0; i < s->cap; i++) {
        key_set_empty(&s->slots[i]);
    }
    return s;
}

void lfw_state_destroy(lfw_state_t *state)
{
    if (!state) {
        return;
    }
    free(state->slots);
    free(state);
}

bool lfw_state_established(const lfw_state_t *state, const lfw_packet_t *packet)
{
    if (!state || !packet) {
        return false;
    }
    if (packet->protocol != LFW_PROTO_TCP && packet->protocol != LFW_PROTO_UDP) {
        return false;
    }

    lfw_conn_key_t key;
    key_from_packet(packet, &key);

    lfw_u32 idx = hash_key(&key) % state->cap;
    for (lfw_u32 n = 0; n < state->cap; n++) {
        lfw_conn_key_t *slot = &state->slots[idx];
        if (key_is_empty(slot)) {
            return false;
        }
        if (key_equal(slot, &key)) {
            return true;
        }
        idx = (idx + 1) % state->cap;
    }
    return false;
}

void lfw_state_add(lfw_state_t *state, const lfw_packet_t *packet)
{
    if (!state || !packet) {
        return;
    }
    if (packet->protocol != LFW_PROTO_TCP && packet->protocol != LFW_PROTO_UDP) {
        return;
    }
    if (state->count >= state->cap) {
        return; /* table full */
    }

    lfw_conn_key_t key;
    key_from_packet(packet, &key);

    lfw_u32 idx = hash_key(&key) % state->cap;
    for (lfw_u32 n = 0; n < state->cap; n++) {
        lfw_conn_key_t *slot = &state->slots[idx];
        if (key_is_empty(slot)) {
            *slot = key;
            state->count++;
            return;
        }
        if (key_equal(slot, &key)) {
            return; /* already present */
        }
        idx = (idx + 1) % state->cap;
    }
}
