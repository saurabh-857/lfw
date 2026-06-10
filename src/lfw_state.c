// SPDX-License-Identifier: GPL-3.0-only

#include "lfw_state.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

// Table size (must be power of two for better distribution)
#define LFW_STATE_TABLE_SIZE 65536

// Timeouts (seconds)
#define LFW_TCP_TIMEOUT 300
#define LFW_UDP_TIMEOUT 60

typedef enum {
    SLOT_EMPTY = 0,
    SLOT_OCCUPIED,
    SLOT_TOMBSTONE
} slot_state_t;

typedef struct {
    lfw_ip_t src_ip;
    lfw_ip_t dst_ip;
    lfw_u16  src_port;
    lfw_u16  dst_port;
    lfw_u8   protocol;
    lfw_u8   state;
    lfw_u64  last_seen;
} lfw_conn_entry_t;

struct lfw_state {
    lfw_conn_entry_t *slots;
    lfw_u32           cap;
    lfw_u32           count;
    pthread_mutex_t   lock;
    pthread_t         cleanup_thread;
    volatile bool     cleanup_running;
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
    e->state = SLOT_EMPTY;
}

// Normalize connection tuple for bidirectional matching
static void normalize_key(const lfw_packet_t *pkt, lfw_conn_entry_t *e)
{
    lfw_ip_t a_ip   = pkt->ip.src;
    lfw_ip_t b_ip   = pkt->ip.dst;
    lfw_u16 a_port = pkt->l4.src_port.port;
    lfw_u16 b_port = pkt->l4.dst_port.port;

    bool swap = false;
    if (a_ip.ip_version == 4) {
        if (a_ip.v4.addr > b_ip.v4.addr || (a_ip.v4.addr == b_ip.v4.addr && a_port > b_port)) {
            swap = true;
        }
    } else {
        int cmp = memcmp(a_ip.v6.addr, b_ip.v6.addr, 16);
        if (cmp > 0 || (cmp == 0 && a_port > b_port)) {
            swap = true;
        }
    }

    if (!swap) {
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
    lfw_u32 h = 0;
    if (e->src_ip.ip_version == 4) {
        h = e->src_ip.v4.addr ^ e->dst_ip.v4.addr;
    } else {
        for (int i = 0; i < 4; i++) {
            h ^= ((lfw_u32*)e->src_ip.v6.addr)[i] ^ ((lfw_u32*)e->dst_ip.v6.addr)[i];
        }
    }
    h ^= ((lfw_u32)e->src_port << 16) | e->dst_port;
    h ^= ((lfw_u32)e->protocol << 24);
    return h;
}

static bool entry_equal(const lfw_conn_entry_t *a,
                        const lfw_conn_entry_t *b)
{
    if (a->src_ip.ip_version != b->src_ip.ip_version ||
        a->src_port != b->src_port ||
        a->dst_port != b->dst_port ||
        a->protocol != b->protocol)
    {
        return false;
    }

    if (a->src_ip.ip_version == 4) {
        return a->src_ip.v4.addr == b->src_ip.v4.addr &&
               a->dst_ip.v4.addr == b->dst_ip.v4.addr;
    } else {
        return memcmp(a->src_ip.v6.addr, b->src_ip.v6.addr, 16) == 0 &&
               memcmp(a->dst_ip.v6.addr, b->dst_ip.v6.addr, 16) == 0;
    }
}

static bool entry_expired(const lfw_conn_entry_t *e, lfw_u64 now)
{
    if (now <= e->last_seen)
        return false;

    if (e->protocol == LFW_PROTO_TCP)
        return (now - e->last_seen) > LFW_TCP_TIMEOUT;

    if (e->protocol == LFW_PROTO_UDP)
        return (now - e->last_seen) > LFW_UDP_TIMEOUT;

    return true;
}

// ------------------------------
// Public API
// ------------------------------

static void *state_cleanup_loop(void *arg)
{
    lfw_state_t *state = (lfw_state_t *)arg;
    while (state->cleanup_running) {
        for (int i = 0; i < 10 && state->cleanup_running; i++) {
            usleep(1000000);
        }
        if (!state->cleanup_running)
            break;
        lfw_state_cleanup(state);
    }
    return NULL;
}

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

    if (pthread_mutex_init(&s->lock, NULL) != 0) {
        free(s->slots);
        free(s);
        return NULL;
    }

    s->cleanup_running = true;
    if (pthread_create(&s->cleanup_thread, NULL, state_cleanup_loop, s) != 0) {
        s->cleanup_running = false;
    }

    return s;
}

void lfw_state_destroy(lfw_state_t *state)
{
    if (!state)
        return;

    if (state->cleanup_running) {
        state->cleanup_running = false;
        pthread_join(state->cleanup_thread, NULL);
    }

    pthread_mutex_destroy(&state->lock);
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

    pthread_mutex_lock(&state->lock);

    for (lfw_u32 i = 0; i < state->cap; i++) {
        lfw_conn_entry_t *slot = &state->slots[idx];

        if (slot->state == SLOT_EMPTY) {
            pthread_mutex_unlock(&state->lock);
            return false;
        }

        if (slot->state == SLOT_OCCUPIED) {
            if (entry_expired(slot, now)) {
                slot->state = SLOT_TOMBSTONE;
                state->count--;
            } else if (entry_equal(slot, &key)) {
                slot->last_seen = now;
                pthread_mutex_unlock(&state->lock);
                return true;
            }
        }

        idx = (idx + 1) % state->cap;
    }

    pthread_mutex_unlock(&state->lock);
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

    lfw_conn_entry_t key = {0};
    normalize_key(packet, &key);
    key.last_seen = now_sec();
    key.state = SLOT_OCCUPIED;

    pthread_mutex_lock(&state->lock);

    if (state->count >= state->cap) {
        pthread_mutex_unlock(&state->lock);
        return;
    }

    lfw_u32 idx = hash_entry(&key) % state->cap;
    int first_tombstone_idx = -1;

    for (lfw_u32 i = 0; i < state->cap; i++) {
        lfw_conn_entry_t *slot = &state->slots[idx];

        if (slot->state == SLOT_EMPTY) {
            int insert_idx = (first_tombstone_idx != -1) ? first_tombstone_idx : (int)idx;
            state->slots[insert_idx] = key;
            state->count++;
            pthread_mutex_unlock(&state->lock);
            return;
        }

        if (slot->state == SLOT_TOMBSTONE) {
            if (first_tombstone_idx == -1) {
                first_tombstone_idx = (int)idx;
            }
        }

        if (slot->state == SLOT_OCCUPIED) {
            if (entry_equal(slot, &key)) {
                slot->last_seen = key.last_seen;
                pthread_mutex_unlock(&state->lock);
                return;
            }
        }

        idx = (idx + 1) % state->cap;
    }

    if (first_tombstone_idx != -1) {
        state->slots[first_tombstone_idx] = key;
        state->count++;
    }

    pthread_mutex_unlock(&state->lock);
}

void lfw_state_cleanup(lfw_state_t *state)
{
    if (!state)
        return;

    lfw_u64 now = now_sec();

    pthread_mutex_lock(&state->lock);

    lfw_u32 tombstones = 0;
    for (lfw_u32 i = 0; i < state->cap; i++) {
        lfw_conn_entry_t *slot = &state->slots[i];
        if (slot->state == SLOT_OCCUPIED) {
            if (entry_expired(slot, now)) {
                slot->state = SLOT_TOMBSTONE;
                state->count--;
            }
        }
        if (slot->state == SLOT_TOMBSTONE) {
            tombstones++;
        }
    }

    // Rebuild hash table if tombstones exceed 25% of capacity to prevent linear probing degradation
    if (tombstones > state->cap / 4) {
        lfw_conn_entry_t *new_slots = calloc(state->cap, sizeof(lfw_conn_entry_t));
        if (new_slots) {
            for (lfw_u32 i = 0; i < state->cap; i++) {
                entry_set_empty(&new_slots[i]);
            }

            lfw_u32 new_count = 0;
            for (lfw_u32 i = 0; i < state->cap; i++) {
                if (state->slots[i].state == SLOT_OCCUPIED) {
                    lfw_conn_entry_t entry = state->slots[i];
                    lfw_u32 idx = hash_entry(&entry) % state->cap;
                    while (new_slots[idx].state == SLOT_OCCUPIED) {
                        idx = (idx + 1) % state->cap;
                    }
                    new_slots[idx] = entry;
                    new_count++;
                }
            }

            free(state->slots);
            state->slots = new_slots;
            state->count = new_count;
        }
    }

    pthread_mutex_unlock(&state->lock);
}

lfw_u32 lfw_state_get_count(lfw_state_t *state)
{
    if (!state)
        return 0;

    pthread_mutex_lock(&state->lock);
    lfw_u32 count = state->count;
    pthread_mutex_unlock(&state->lock);
    return count;
}
