/**
 * WFSPLIT: traffic-splitting multipath scheduler for website-fingerprinting
 * (WF) defense research.
 *
 * Unlike WLB, it never pins a flow to a path and never weights paths by
 * measured goodput: every application packet is assigned by a split policy
 * whose only goal is to control what an observer on ONE path gets to see.
 * See xqc_scheduler_wfsplit.c for the policies and their knobs.
 */

#ifndef _XQC_SCHEDULER_WFSPLIT_H_INCLUDED_
#define _XQC_SCHEDULER_WFSPLIT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_wfsplit_scheduler_cb;

/* Per-path counters of what the scheduler has handed out. Internal: tests
 * and measurement read the realised split through it. */
typedef struct {
    uint64_t path_id;
    uint64_t tx_bytes;
    uint64_t tx_pkts;
    double   weight;   /* current BWR weight (0 under the equal policy) */
} xqc_wfsplit_path_stats_t;

int xqc_wfsplit_scheduler_copy_path_stats(void *scheduler,
                                          xqc_wfsplit_path_stats_t *out,
                                          size_t capacity, size_t *out_count);

#endif /* _XQC_SCHEDULER_WFSPLIT_H_INCLUDED_ */
