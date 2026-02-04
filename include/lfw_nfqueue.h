#ifndef LFW_NFQUEUE_H
#define LFW_NFQUEUE_H

/*
 * lfw - Linux Firewall
 * Netfilter (NFQUEUE) integration
 */

#include "lfw_engine.h"

/*
 * Start NFQUEUE processing loop.
 * This call blocks.
 */
lfw_status_t lfw_nfqueue_run(const lfw_engine_t *engine, unsigned int queue_num);

#endif /* LFW_NFQUEUE_H */
