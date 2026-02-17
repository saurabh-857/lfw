#include "lfw_state.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Table size (must be power of two for better distribution)
#define LFW_STATE_TABLE_SIZE 4096

// Timeouts (seconds)
#define LFW_TCP_TIMEOUT 300
#define LFW_UDP_TIMEOUT 60

#define LFW_EMPTY_MARK 0xFFFFFFFFu

typedef struct {
    lfw_u32 src_ip;
    lfw_u32 dst_ip;
    lfw_u16 src_port;
    lfw_u16 dst_port;
    lfw_u8  protocol;
    lfw_u8  _pad;
    lfw_u64 last_seen;
} lfw_conn_entry_t;

struct lfw_state {
    lfw_conn_entry_t *slots;
    lfw_u32           cap;
    lfw_u32           count;
};

// ------------------------------
// Utility
// ------------------------------

static lfw_u64 now_sec(void)
{
    return (lfw_u64)time(NULL);
}

static void entry_set_empty(lfw_conn_entry_t *e)
{
    e->src_ip = LFW_EMPTY_MARK;
    e->dst_ip = LFW_EMPTY_MARK;
}

static bool entry_is_empty(const lfw_conn_entry_t *e)
{
    return (e->src_ip == LFW_EMPTY_MARK &&
            e->dst_ip == LFW_EMPTY_MARK);
}

// Normalize connection tuple for bidirectional matching
static void normalize_key(const lfw_packet_t *pkt, lfw_conn_entry_t *e)
{
    lfw_u32 a_ip   = pkt->ip4.src.addr;
    lfw_u32 b_ip   = pkt->ip4.dst.addr;
    lfw_u16 a_port = pkt->l4.src_port.port;
    lfw_u16 b_port = pkt->l4.dst_port.port;

    // Deterministic ordering
    if (a_ip < b_ip || (a_ip == b_ip && a_port <= b_port)) {
        e->src_ip   = a_ip;
        e->dst_ip   = b_ip;
        e->src_port = a_port;
        e->dst_port = b_port;
    } else {
        e->src_ip   = b_ip;
        e->dst_ip   = a_ip;
        e->src_port = b_port;
        e->dst_port = a_port;
    }

    e->protocol = (lfw_u8)pkt->protocol;
}

static lfw_u32 hash_entry(const lfw_conn_entry_t *e)
{
    lfw_u32 h = e->src_ip ^ e->dst_ip;
    h ^= ((lfw_u32)e->src_port << 16) | e->dst_port;
    h ^= ((lfw_u32)e->protocol << 24);
    return h;
}

static bool entry_equal(const lfw_conn_entry_t *a,
                        const lfw_conn_entry_t *b)
{
    return a->src_ip   == b->src_ip   &&
            a->dst_ip   == b->dst_ip   &&
            a->src_port == b->src_port &&
            a->dst_port == b->dst_port &&
            a->protocol == b->protocol;
}

static bool entry_expired(const lfw_conn_entry_t *e, lfw_u64 now)
{
    if (e->protocol == LFW_PROTO_TCP)
        return (now - e->last_seen) > LFW_TCP_TIMEOUT;

    if (e->protocol == LFW_PROTO_UDP)
        return (now - e->last_seen) > LFW_UDP_TIMEOUT;

    return true;
}

// ------------------------------
// Public API
// ------------------------------

lfw_state_t *lfw_state_create(void)
{
    lfw_state_t *s = malloc(sizeof(*s));
    if (!s)
        return NULL;

    s->cap   = LFW_STATE_TABLE_SIZE;
    s->count = 0;
    s->slots = calloc(s->cap, sizeof(lfw_conn_entry_t));
    if (!s->slots) {
        free(s);
        return NULL;
    }

    for (lfw_u32 i = 0; i < s->cap; i++)
        entry_set_empty(&s->slots[i]);

    return s;
}

void lfw_state_destroy(lfw_state_t *state)
{
    if (!state)
        return;

    free(state->slots);
    free(state);
}

bool lfw_state_established(lfw_state_t *state,
                            const lfw_packet_t *packet)
{
    if (!state || !packet)
        return false;

    if (packet->protocol != LFW_PROTO_TCP &&
        packet->protocol != LFW_PROTO_UDP)
        return false;

    lfw_conn_entry_t key = {0};
    normalize_key(packet, &key);

    lfw_u32 idx = hash_entry(&key) % state->cap;
    lfw_u64 now = now_sec();

    for (lfw_u32 i = 0; i < state->cap; i++) {

        lfw_conn_entry_t *slot = &state->slots[idx];

        if (entry_is_empty(slot))
            return false;

        // Remove expired entries lazily
        if (entry_expired(slot, now)) {
            entry_set_empty(slot);
            state->count--;
            return false;
        }

        if (entry_equal(slot, &key)) {
            slot->last_seen = now; // refresh activity
            return true;
        }

        idx = (idx + 1) % state->cap;
    }

    return false;
}

void lfw_state_add(lfw_state_t *state,
                    const lfw_packet_t *packet)
{
    if (!state || !packet)
        return;

    if (packet->protocol != LFW_PROTO_TCP &&
        packet->protocol != LFW_PROTO_UDP)
        return;

    if (state->count >= state->cap)
        return;

    lfw_conn_entry_t key = {0};
    normalize_key(packet, &key);
    key.last_seen = now_sec();

    lfw_u32 idx = hash_entry(&key) % state->cap;

    for (lfw_u32 i = 0; i < state->cap; i++) {

        lfw_conn_entry_t *slot = &state->slots[idx];

        if (entry_is_empty(slot)) {
            *slot = key;
            state->count++;
            return;
        }

        if (entry_equal(slot, &key)) {
            slot->last_seen = key.last_seen;
            return;
        }

        idx = (idx + 1) % state->cap;
    }
}
