#ifndef LFW_STATE_H
#define LFW_STATE_H

/*
 * lfw - Linux Firewall
 * Connection state table for stateful filtering.
 *
 * Tracks allowed connections (5-tuple). Once a new connection is allowed
 * by the rule engine, subsequent packets of the same connection are
 * accepted without re-evaluating rules.
 */

#include "lfw_types.h"
#include "lfw_packet.h"

/* ==============================
 * Connection state table
 * ============================== */
typedef struct lfw_state lfw_state_t;

/*
 * Create a connection state table (fixed size, internal hash).
 * Returns NULL on allocation failure.
 */
lfw_state_t *lfw_state_create(void);

/*
 * Destroy state table and free memory.
 */
void lfw_state_destroy(lfw_state_t *state);

/*
 * Check if this packet belongs to an already-allowed connection.
 * Returns true if the 5-tuple is in the table (established).
 */
bool lfw_state_established(const lfw_state_t *state, const lfw_packet_t *packet);

/*
 * Add this packet's connection to the allowed table (call after allowing
 * a new connection). No-op if table is full.
 */
void lfw_state_add(lfw_state_t *state, const lfw_packet_t *packet);

#endif /* LFW_STATE_H */
