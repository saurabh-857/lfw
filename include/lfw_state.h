#ifndef LFW_STATE_H
#define LFW_STATE_H

#include "lfw_types.h"
#include "lfw_packet.h"

// Opaque state table
typedef struct lfw_state lfw_state_t;

// Create state table
lfw_state_t *lfw_state_create(void);

// Destroy state table
void lfw_state_destroy(lfw_state_t *state);

// Check if packet belongs to established connection
bool lfw_state_established(
    lfw_state_t *state,
    const lfw_packet_t *packet
);

// Add new connection
void lfw_state_add(
    lfw_state_t *state,
    const lfw_packet_t *packet
);

#endif
