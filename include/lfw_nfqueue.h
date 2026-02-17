#ifndef LFW_NFQUEUE_H
#define LFW_NFQUEUE_H

#include "lfw_engine.h"

// Start NFQUEUE loop
lfw_status_t lfw_nfqueue_run(
    const lfw_engine_t *engine,
    unsigned int queue_num
);

#endif
