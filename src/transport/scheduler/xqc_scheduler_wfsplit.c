/**
 * WFSPLIT: traffic-splitting multipath scheduler for website-fingerprinting
 * (WF) defense research.
 *
 * Threat model: a passive observer sits on ONE access path (one ISP / one
 * radio link) and records the encrypted tunnel trace it sees there. The
 * defense goal is that no single path carries a trace from which the page
 * can be identified. WLB is the wrong tool for that: it pins every inner
 * TCP connection to one path (so a page whose bytes come mostly from one
 * connection is seen almost whole on one path) and weights paths by measured
 * goodput (so the split follows link capacity, which is stable and therefore
 * learnable). This scheduler does neither.
 *
 * Packet classes:
 *   - reinjected replica -> lowest-SRTT other path (reinjection is off by
 *     default in mqvpn; when on, a replica reveals the original's size and
 *     timing on the second path, so leave it off for WF experiments).
 *   - everything else, regardless of po_flow_hash (DATAGRAM, STREAM and
 *     control alike) -> split policy below.
 *   Packets bound to a specific path before scheduling (ACK_MP returned on
 *   the path it acknowledges, PATH_CHALLENGE/RESPONSE, PTO probes) never
 *   reach this callback; see xqc_packet_out_on_specific_path.
 *
 * Split policies (MQVPN_WFS_POLICY):
 *   rand (default)   Random runs, after HyWF (Henri et al., PoPETs 2020).
 *                    Per page, path weights are drawn from a flat Dirichlet
 *                    (for two paths: share ~ U[0,1]) and a mean run length
 *                    m ~ U[MQVPN_WFS_RUN_MEAN_MIN, MQVPN_WFS_RUN_MEAN_MAX]
 *                    packets. Packets go out in runs whose length is
 *                    geometric with mean m; each run's path is drawn from the
 *                    weights (it may repeat). Geometric runs are memoryless:
 *                    the chance that the next packet switches path is the
 *                    same whatever happened before, so no model of the past
 *                    assignments predicts a switch better than that constant.
 *   bwr              Batched Weighted Random, after TrafficSliver (De la
 *                    Cadena et al., CCS 2020): same per-page weights, but
 *                    runs ("batches") of U[MQVPN_WFS_BATCH_MIN, _MAX]
 *                    packets. Bounded uniform batches are NOT memoryless: once
 *                    a batch has run BATCH_MIN packets a switch becomes ever
 *                    more likely, which a model can learn. Kept for comparison
 *                    with the literature.
 *   equal            Baseline only, NOT a defense. Deterministic balance:
 *                    every packet goes to the path with the lowest byte (or
 *                    packet, MQVPN_WFS_UNIT=packets) credit. With similar
 *                    packet sizes that is plain alternation A,B,A,B -- round
 *                    robin -- and each observer sees a fixed thinning of the
 *                    full trace. TrafficSliver and HyWF both found round robin
 *                    and fixed 50/50 splitting nearly useless against an
 *                    attacker that trains on split traces.
 *   Per-page weights (rand, bwr) are redrawn after an idle gap of
 *   MQVPN_WFS_RESAMPLE_IDLE_MS (a proxy for "a new page load started" -- the
 *   transport cannot see page boundaries) and/or every MQVPN_WFS_RESAMPLE_MS.
 *   To add your own policy, write a wfs_pick_<name>() with the same signature
 *   as wfs_pick_equal()/wfs_pick_runs(), add it to wfs_policy_t, to the switch
 *   in wfs_pick() and parse its name in wfs_load_config().
 *
 * Randomness: by default every random draw comes from BoringSSL's CSPRNG
 * (RAND_bytes, buffered), so the split cannot be predicted by recovering a
 * generator state. MQVPN_WFS_SEED=<n> switches to a seeded xorshift64*
 * generator for reproducible experiments only -- never deploy with it.
 *
 * Congestion-window blocking (MQVPN_WFS_ON_BLOCK):
 *   wait (default)   If the path the policy chose has no cwnd room, return no
 *                    path and report cc_blocked: the packet waits for that
 *                    path. The realised split is exactly the policy's, at the
 *                    price of throughput = what the slowest share allows.
 *   spill            Send on another path that has room. Better throughput,
 *                    but the realised split then drifts toward link capacity
 *                    -- the very signal the policy is meant to hide.
 *
 * Path health: a path that is not ACTIVE, is FROZEN, has a socket error, or
 * has reached WFS_PTO_EVICT_THRESH consecutive PTOs is skipped, the same
 * rule WLB uses. When a path (re)enters the healthy set its credit is aligned
 * to the lowest credit of the paths that stayed healthy, so a returning or
 * late-joining path does not receive a catch-up burst under `equal`.
 *
 * Research instrumentation: MQVPN_WFS_DECISION_LOG=<file> appends one line
 * per scheduled packet, "t_us,path_id,bytes", so the realised assignment
 * sequence can be analysed. The file stays open for the process lifetime.
 *
 * All knobs are read from the environment once per connection (at scheduler
 * init). That is a research convenience, not a config surface: set them in
 * the environment of BOTH the client (uplink) and the server (downlink)
 * processes.
 */

#include "src/transport/scheduler/xqc_scheduler_wfsplit.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/common/xqc_time.h"

#include <openssl/rand.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- constants ---------- */

#define WFS_MAX_PATHS          8     /* split state slots; extra paths are ignored */
#define WFS_PTO_EVICT_THRESH   3     /* same blackhole rule as WLB */
#define WFS_NO_SLOT            (-1)
#define WFS_STATS_LOG_US       (1000ULL * 1000)
#define WFS_RAND_BUF           512

#define WFS_DEF_BATCH_MIN      50
#define WFS_DEF_BATCH_MAX      70
#define WFS_DEF_RUN_MEAN_MIN   10
#define WFS_DEF_RUN_MEAN_MAX   50
#define WFS_DEF_RESAMPLE_IDLE_MS 1000

typedef enum {
    WFS_POLICY_RAND  = 0,
    WFS_POLICY_BWR   = 1,
    WFS_POLICY_EQUAL = 2,
} wfs_policy_t;

typedef enum {
    WFS_BLOCK_WAIT  = 0,
    WFS_BLOCK_SPILL = 1,
} wfs_block_t;

/* ---------- data types ---------- */

typedef struct {
    xqc_bool_t used;
    uint64_t   path_id;
    uint64_t   credit;      /* equal policy: units handed out (aligned on rejoin) */
    uint64_t   tx_bytes;    /* raw counters, never aligned */
    uint64_t   tx_pkts;
    uint64_t   seen_gen;    /* last get_path generation this path was healthy */
    double     weight;      /* rand/bwr: raw Exp(1) draw; normalised at use */
} wfs_slot_t;

typedef struct {
    wfs_slot_t   slots[WFS_MAX_PATHS];
    uint64_t     gen;

    /* config */
    wfs_policy_t policy;
    wfs_block_t  on_block;
    xqc_bool_t   unit_packets;
    uint32_t     batch_min;
    uint32_t     batch_max;
    uint32_t     run_mean_min;
    uint32_t     run_mean_max;
    uint64_t     resample_us;       /* 0 = no periodic redraw */
    uint64_t     resample_idle_us;  /* 0 = no idle-gap redraw */

    /* run state (rand, bwr) */
    int          run_slot;
    uint64_t     run_left;
    double       run_mean;          /* rand: per-page mean run length */
    xqc_bool_t   weights_drawn;
    uint64_t     next_resample_us;
    uint64_t     last_payload_us;

    /* randomness */
    xqc_bool_t   seeded;            /* test-only deterministic generator */
    uint64_t     rng;
    uint8_t      rbuf[WFS_RAND_BUF];
    size_t       rpos;

    FILE        *dlog;
    uint64_t     last_log_us;
    xqc_log_t   *log;
} xqc_wfs_scheduler_t;

/* ---------- small helpers ---------- */

static uint64_t
wfs_env_u64(const char *name, uint64_t def, uint64_t lo, uint64_t hi)
{
    const char *v = getenv(name);
    if (v == NULL || *v == '\0') {
        return def;
    }
    char *end = NULL;
    unsigned long long x = strtoull(v, &end, 10);
    if (end == v || *end != '\0' || x < lo || x > hi) {
        return def;
    }
    return (uint64_t)x;
}

static uint64_t
wfs_splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t
wfs_rand64(xqc_wfs_scheduler_t *s)
{
    if (s->seeded) {
        /* xorshift64*: reproducible, linear, predictable -- tests only. */
        uint64_t x = s->rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s->rng = x;
        return x * 0x2545F4914F6CDD1DULL;
    }
    if (s->rpos + sizeof(uint64_t) > sizeof(s->rbuf)) {
        RAND_bytes(s->rbuf, sizeof(s->rbuf));   /* BoringSSL aborts rather than fail */
        s->rpos = 0;
    }
    uint64_t v;
    memcpy(&v, s->rbuf + s->rpos, sizeof(v));
    s->rpos += sizeof(v);
    return v;
}

/* Uniform in (0, 1]. */
static double
wfs_rand_unit(xqc_wfs_scheduler_t *s)
{
    return ((double)(wfs_rand64(s) >> 11) + 1.0) * (1.0 / 9007199254740992.0);
}

/* Uniform integer in [lo, hi], without modulo bias. */
static uint64_t
wfs_rand_range(xqc_wfs_scheduler_t *s, uint64_t lo, uint64_t hi)
{
    if (hi <= lo) {
        return lo;
    }
    uint64_t span = hi - lo + 1;
    uint64_t limit = UINT64_MAX - (UINT64_MAX % span);
    uint64_t r;
    do {
        r = wfs_rand64(s);
    } while (r >= limit);
    return lo + r % span;
}

/* Geometric on {1, 2, ...} with the given mean: P(len = k) = p (1-p)^(k-1),
 * p = 1/mean. Memoryless, so the remaining length of a run never depends on
 * how long it has already lasted. */
static uint64_t
wfs_rand_geometric(xqc_wfs_scheduler_t *s, double mean)
{
    if (mean <= 1.0) {
        return 1;
    }
    double p = 1.0 / mean;
    double k = floor(log(wfs_rand_unit(s)) / log(1.0 - p));
    if (k > 1e9) {
        k = 1e9;
    }
    return 1 + (uint64_t)k;
}

/* Exp(1) draws normalised over any subset of paths form a flat Dirichlet on
 * that subset, so the weights stay well defined when paths come and go. */
static double
wfs_draw_weight(xqc_wfs_scheduler_t *s)
{
    return -log(wfs_rand_unit(s));
}

static void
wfs_load_config(xqc_wfs_scheduler_t *s)
{
    const char *p = getenv("MQVPN_WFS_POLICY");
    if (p && strcmp(p, "bwr") == 0) {
        s->policy = WFS_POLICY_BWR;
    } else if (p && strcmp(p, "equal") == 0) {
        s->policy = WFS_POLICY_EQUAL;
    } else {
        s->policy = WFS_POLICY_RAND;
    }

    const char *b = getenv("MQVPN_WFS_ON_BLOCK");
    s->on_block = (b && strcmp(b, "spill") == 0) ? WFS_BLOCK_SPILL : WFS_BLOCK_WAIT;

    const char *u = getenv("MQVPN_WFS_UNIT");
    s->unit_packets = (u && strcmp(u, "packets") == 0) ? XQC_TRUE : XQC_FALSE;

    s->batch_min = (uint32_t)wfs_env_u64("MQVPN_WFS_BATCH_MIN", WFS_DEF_BATCH_MIN, 1, 100000);
    s->batch_max = (uint32_t)wfs_env_u64("MQVPN_WFS_BATCH_MAX", WFS_DEF_BATCH_MAX, 1, 100000);
    if (s->batch_max < s->batch_min) {
        s->batch_max = s->batch_min;
    }
    s->run_mean_min = (uint32_t)wfs_env_u64("MQVPN_WFS_RUN_MEAN_MIN", WFS_DEF_RUN_MEAN_MIN,
                                            1, 100000);
    s->run_mean_max = (uint32_t)wfs_env_u64("MQVPN_WFS_RUN_MEAN_MAX", WFS_DEF_RUN_MEAN_MAX,
                                            1, 100000);
    if (s->run_mean_max < s->run_mean_min) {
        s->run_mean_max = s->run_mean_min;
    }
    s->resample_us = 1000ULL * wfs_env_u64("MQVPN_WFS_RESAMPLE_MS", 0, 0, 3600ULL * 1000);
    s->resample_idle_us = 1000ULL * wfs_env_u64("MQVPN_WFS_RESAMPLE_IDLE_MS",
                                                WFS_DEF_RESAMPLE_IDLE_MS, 0, 3600ULL * 1000);

    uint64_t seed = wfs_env_u64("MQVPN_WFS_SEED", 0, 1, UINT64_MAX);
    if (seed != 0) {
        s->seeded = XQC_TRUE;
        s->rng = wfs_splitmix64(&seed);
        if (s->rng == 0) {
            s->rng = 0x9E3779B97F4A7C15ULL;   /* xorshift must not start at 0 */
        }
    }
    s->rpos = sizeof(s->rbuf);                /* force a CSPRNG refill on first use */

    const char *dl = getenv("MQVPN_WFS_DECISION_LOG");
    if (dl && *dl) {
        s->dlog = fopen(dl, "a");
        if (s->dlog) {
            setvbuf(s->dlog, NULL, _IOLBF, 0);
            fprintf(s->dlog, "# conn %p policy %d\n", (void *)s, (int)s->policy);
        }
    }
}

/* ---------- path health ---------- */

static xqc_bool_t
wfs_path_transport_ok(xqc_path_ctx_t *path)
{
    return path->path_state == XQC_PATH_STATE_ACTIVE
           && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN
           && !(path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR);
}

static xqc_bool_t
wfs_path_blackholed(xqc_path_ctx_t *path)
{
    return path->path_send_ctl != NULL
           && xqc_send_ctl_get_effective_pto_count(path->path_send_ctl)
              >= WFS_PTO_EVICT_THRESH;
}

/* ---------- slot bookkeeping ---------- */

static int
wfs_slot_find(xqc_wfs_scheduler_t *s, uint64_t path_id)
{
    for (int i = 0; i < WFS_MAX_PATHS; i++) {
        if (s->slots[i].used && s->slots[i].path_id == path_id) {
            return i;
        }
    }
    return WFS_NO_SLOT;
}

static int
wfs_slot_get(xqc_wfs_scheduler_t *s, uint64_t path_id)
{
    int i = wfs_slot_find(s, path_id);
    if (i != WFS_NO_SLOT) {
        return i;
    }
    /* Reuse a free slot, else the one unseen for longest (a path that left
     * long ago). Never evict a slot seen in the current generation. */
    int victim = WFS_NO_SLOT;
    for (i = 0; i < WFS_MAX_PATHS; i++) {
        if (!s->slots[i].used) {
            victim = i;
            break;
        }
        if (s->slots[i].seen_gen == s->gen) {
            continue;
        }
        if (victim == WFS_NO_SLOT || s->slots[i].seen_gen < s->slots[victim].seen_gen) {
            victim = i;
        }
    }
    if (victim == WFS_NO_SLOT) {
        return WFS_NO_SLOT;
    }
    if (s->run_slot == victim) {
        s->run_slot = WFS_NO_SLOT;
        s->run_left = 0;
    }
    memset(&s->slots[victim], 0, sizeof(s->slots[victim]));
    s->slots[victim].used = XQC_TRUE;
    s->slots[victim].path_id = path_id;
    s->slots[victim].weight = wfs_draw_weight(s);
    return victim;
}

/* Collect healthy paths into cand[] (slot indexes + path pointers) and
 * advance the health generation. Paths that were not healthy in the previous
 * generation get their credit aligned to the lowest credit among paths that
 * were, so they neither starve nor receive a catch-up burst. When nothing is
 * healthy, fall back to transport-OK paths ignoring the PTO rule, so a
 * connection whose every path is blackholed can still try to send. */
static int
wfs_collect(xqc_wfs_scheduler_t *s, xqc_connection_t *conn,
            int *cand_slot, xqc_path_ctx_t **cand_path)
{
    uint64_t prev_gen = s->gen;
    s->gen++;

    int n = 0;
    for (int pass = 0; pass < 2 && n == 0; pass++) {
        xqc_list_head_t *pos, *next;
        xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
            xqc_path_ctx_t *path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
            if (!wfs_path_transport_ok(path)) {
                continue;
            }
            if (pass == 0 && wfs_path_blackholed(path)) {
                continue;
            }
            if (n >= WFS_MAX_PATHS) {
                break;
            }
            int slot = wfs_slot_get(s, path->path_id);
            if (slot == WFS_NO_SLOT) {
                continue;
            }
            cand_slot[n] = slot;
            cand_path[n] = path;
            n++;
        }
    }

    /* Alignment: lowest credit among paths healthy last generation too. */
    xqc_bool_t have_floor = XQC_FALSE;
    uint64_t floor_credit = 0;
    for (int i = 0; i < n; i++) {
        wfs_slot_t *sl = &s->slots[cand_slot[i]];
        if (prev_gen != 0 && sl->seen_gen == prev_gen) {
            if (!have_floor || sl->credit < floor_credit) {
                floor_credit = sl->credit;
                have_floor = XQC_TRUE;
            }
        }
    }
    for (int i = 0; i < n; i++) {
        wfs_slot_t *sl = &s->slots[cand_slot[i]];
        if (have_floor && sl->seen_gen != prev_gen) {
            sl->credit = floor_credit;
            xqc_log(s->log, XQC_LOG_INFO, "|wfsplit|path_join|path:%ui|credit:%ui|",
                    sl->path_id, sl->credit);
        }
        sl->seen_gen = s->gen;
    }
    return n;
}

/* ---------- split policies ----------
 *
 * Each policy returns the index into cand[] of the path this packet SHOULD
 * take, ignoring cwnd. `exclude` is a cand[] index to skip (used to find a
 * spill target), or -1. Return -1 if no candidate qualifies. */

static int
wfs_pick_equal(xqc_wfs_scheduler_t *s, int n, const int *cand_slot, int exclude)
{
    int best = -1;
    for (int i = 0; i < n; i++) {
        if (i == exclude) {
            continue;
        }
        if (best < 0 || s->slots[cand_slot[i]].credit < s->slots[cand_slot[best]].credit) {
            best = i;
        }
    }
    return best;
}

static void
wfs_maybe_redraw(xqc_wfs_scheduler_t *s, uint64_t now_us)
{
    xqc_bool_t redraw = !s->weights_drawn;
    if (s->resample_us && now_us >= s->next_resample_us) {
        redraw = XQC_TRUE;
    }
    if (s->resample_idle_us && s->last_payload_us != 0
        && now_us - s->last_payload_us >= s->resample_idle_us)
    {
        redraw = XQC_TRUE;
    }
    if (!redraw) {
        return;
    }
    for (int i = 0; i < WFS_MAX_PATHS; i++) {
        if (s->slots[i].used) {
            s->slots[i].weight = wfs_draw_weight(s);
        }
    }
    s->run_mean = (double)wfs_rand_range(s, s->run_mean_min, s->run_mean_max);
    s->weights_drawn = XQC_TRUE;
    s->next_resample_us = now_us + s->resample_us;
    s->run_slot = WFS_NO_SLOT;   /* new weights start a new run */
    s->run_left = 0;
    xqc_log(s->log, XQC_LOG_INFO, "|wfsplit|redraw|run_mean:%ui|", (uint64_t)s->run_mean);
}

static int
wfs_pick_weighted(xqc_wfs_scheduler_t *s, int n, const int *cand_slot, int exclude)
{
    double total = 0;
    for (int i = 0; i < n; i++) {
        if (i != exclude) {
            total += s->slots[cand_slot[i]].weight;
        }
    }
    if (total <= 0) {
        return wfs_pick_equal(s, n, cand_slot, exclude);
    }
    double r = wfs_rand_unit(s) * total;
    int last = -1;
    for (int i = 0; i < n; i++) {
        if (i == exclude) {
            continue;
        }
        last = i;
        r -= s->slots[cand_slot[i]].weight;
        if (r <= 0) {
            return i;
        }
    }
    return last;   /* rounding */
}

/* rand and bwr: runs of packets on one path, each run's path drawn from the
 * per-page weights; they differ only in the run-length distribution. */
static int
wfs_pick_runs(xqc_wfs_scheduler_t *s, int n, const int *cand_slot, int exclude,
              uint64_t now_us)
{
    if (exclude >= 0) {
        /* Spill target: weighted among the rest; the run is untouched. */
        return wfs_pick_weighted(s, n, cand_slot, exclude);
    }
    wfs_maybe_redraw(s, now_us);

    if (s->run_left > 0 && s->run_slot != WFS_NO_SLOT) {
        for (int i = 0; i < n; i++) {
            if (cand_slot[i] == s->run_slot) {
                return i;
            }
        }
        /* Run path left the healthy set: start a new run. */
    }
    int pick = wfs_pick_weighted(s, n, cand_slot, -1);
    if (pick >= 0) {
        s->run_slot = cand_slot[pick];
        s->run_left = s->policy == WFS_POLICY_BWR
                      ? wfs_rand_range(s, s->batch_min, s->batch_max)
                      : wfs_rand_geometric(s, s->run_mean);
    }
    return pick;
}

static int
wfs_pick(xqc_wfs_scheduler_t *s, int n, const int *cand_slot, int exclude,
         uint64_t now_us)
{
    switch (s->policy) {
    case WFS_POLICY_RAND:
    case WFS_POLICY_BWR:   return wfs_pick_runs(s, n, cand_slot, exclude, now_us);
    case WFS_POLICY_EQUAL: return wfs_pick_equal(s, n, cand_slot, exclude);
    }
    return wfs_pick_equal(s, n, cand_slot, exclude);
}

/* Charge a sent packet to its path. */
static void
wfs_account(xqc_wfs_scheduler_t *s, int slot, xqc_packet_out_t *po, uint64_t now_us)
{
    wfs_slot_t *sl = &s->slots[slot];
    uint64_t bytes = po->po_used_size;
    sl->credit += s->unit_packets ? 1 : bytes;
    sl->tx_bytes += bytes;
    sl->tx_pkts++;
    if (slot == s->run_slot && s->run_left > 0) {
        s->run_left--;
    }
    s->last_payload_us = now_us;

    if (s->dlog) {
        fprintf(s->dlog, "%llu,%llu,%llu\n", (unsigned long long)now_us,
                (unsigned long long)sl->path_id, (unsigned long long)bytes);
    }

    if (now_us - s->last_log_us >= WFS_STATS_LOG_US) {
        s->last_log_us = now_us;
        uint64_t tot = 0;
        for (int i = 0; i < WFS_MAX_PATHS; i++) {
            tot += s->slots[i].used ? s->slots[i].tx_bytes : 0;
        }
        for (int i = 0; i < WFS_MAX_PATHS; i++) {
            if (!s->slots[i].used || tot == 0) {
                continue;
            }
            xqc_log(s->log, XQC_LOG_INFO,
                    "|wfsplit|stats|path:%ui|tx_bytes:%ui|tx_pkts:%ui|share_permille:%ui|",
                    s->slots[i].path_id, s->slots[i].tx_bytes, s->slots[i].tx_pkts,
                    (uint64_t)(s->slots[i].tx_bytes * 1000 / tot));
        }
    }
}

/* ---------- scheduler callback interface ---------- */

static size_t
xqc_wfsplit_scheduler_size(void)
{
    return sizeof(xqc_wfs_scheduler_t);
}

static const char *
wfs_policy_name(wfs_policy_t p)
{
    switch (p) {
    case WFS_POLICY_RAND:  return "rand";
    case WFS_POLICY_BWR:   return "bwr";
    case WFS_POLICY_EQUAL: return "equal";
    }
    return "?";
}

static void
xqc_wfsplit_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    (void)param;
    xqc_wfs_scheduler_t *s = (xqc_wfs_scheduler_t *)scheduler;
    memset(s, 0, sizeof(*s));
    s->log = log;
    s->run_slot = WFS_NO_SLOT;
    wfs_load_config(s);
    xqc_log(log, XQC_LOG_INFO,
            "|wfsplit|init|policy:%s|on_block:%s|unit:%s|batch:%ud-%ud|run_mean:%ud-%ud|"
            "resample_ms:%ui|resample_idle_ms:%ui|rng:%s|",
            wfs_policy_name(s->policy),
            s->on_block == WFS_BLOCK_SPILL ? "spill" : "wait",
            s->unit_packets ? "packets" : "bytes",
            s->batch_min, s->batch_max, s->run_mean_min, s->run_mean_max,
            s->resample_us / 1000, s->resample_idle_us / 1000,
            s->seeded ? "seeded-xorshift(TEST ONLY)" : "csprng");
}

static xqc_path_ctx_t *
wfs_reinject_path(xqc_packet_out_t *packet_out, int n, xqc_path_ctx_t **cand_path,
                  int check_cwnd)
{
    xqc_path_ctx_t *best = NULL;
    uint64_t best_srtt = UINT64_MAX;
    for (int i = 0; i < n; i++) {
        xqc_path_ctx_t *path = cand_path[i];
        if (path->path_id == packet_out->po_path_id) {
            continue;
        }
        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }
        uint64_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (srtt < best_srtt) {
            best_srtt = srtt;
            best = path;
        }
    }
    return best;
}

static xqc_path_ctx_t *
xqc_wfsplit_scheduler_get_path(void *scheduler, xqc_connection_t *conn,
                               xqc_packet_out_t *packet_out, int check_cwnd,
                               int reinject, xqc_bool_t *cc_blocked)
{
    xqc_wfs_scheduler_t *s = (xqc_wfs_scheduler_t *)scheduler;
    int cand_slot[WFS_MAX_PATHS];
    xqc_path_ctx_t *cand_path[WFS_MAX_PATHS];

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    int n = wfs_collect(s, conn, cand_slot, cand_path);
    if (n == 0) {
        return NULL;
    }

    if (reinject) {
        return wfs_reinject_path(packet_out, n, cand_path, check_cwnd);
    }

    uint64_t now_us = xqc_monotonic_timestamp();
    int want = wfs_pick(s, n, cand_slot, -1, now_us);
    if (want < 0) {
        return NULL;
    }

    if (xqc_scheduler_check_path_can_send(cand_path[want], packet_out, check_cwnd)) {
        wfs_account(s, cand_slot[want], packet_out, now_us);
        return cand_path[want];
    }

    if (s->on_block == WFS_BLOCK_SPILL) {
        /* Policy's second choice; enough for the two-path setting this
         * scheduler targets. */
        int alt = wfs_pick(s, n, cand_slot, want, now_us);
        if (alt >= 0
            && xqc_scheduler_check_path_can_send(cand_path[alt], packet_out, check_cwnd))
        {
            wfs_account(s, cand_slot[alt], packet_out, now_us);
            return cand_path[alt];
        }
    }

    /* Wait for the chosen path's cwnd to open. Nothing was charged and the
     * run state is unchanged, so the same decision is made when xquic asks
     * again. */
    if (cc_blocked) {
        *cc_blocked = XQC_TRUE;
    }
    return NULL;
}

static void
xqc_wfsplit_scheduler_handle_path_event(void *scheduler, xqc_path_ctx_t *path,
                                        xqc_scheduler_path_event_t event,
                                        void *event_arg)
{
    /* Health is re-evaluated on every get_path; nothing to do here. */
    (void)scheduler; (void)path; (void)event; (void)event_arg;
}

static void
xqc_wfsplit_scheduler_handle_conn_event(void *scheduler, xqc_connection_t *conn,
                                        xqc_scheduler_conn_event_t event,
                                        void *event_arg)
{
    (void)scheduler; (void)conn; (void)event; (void)event_arg;
}

int
xqc_wfsplit_scheduler_copy_path_stats(void *scheduler, xqc_wfsplit_path_stats_t *out,
                                      size_t capacity, size_t *out_count)
{
    if (scheduler == NULL || out_count == NULL || (capacity > 0 && out == NULL)) {
        return -XQC_EPARAM;
    }
    xqc_wfs_scheduler_t *s = (xqc_wfs_scheduler_t *)scheduler;
    size_t n = 0;
    for (int i = 0; i < WFS_MAX_PATHS; i++) {
        if (!s->slots[i].used) {
            continue;
        }
        if (n < capacity) {
            out[n].path_id = s->slots[i].path_id;
            out[n].tx_bytes = s->slots[i].tx_bytes;
            out[n].tx_pkts = s->slots[i].tx_pkts;
            out[n].weight = s->policy == WFS_POLICY_EQUAL ? 0 : s->slots[i].weight;
        }
        n++;
    }
    *out_count = n;
    return XQC_OK;
}

const xqc_scheduler_callback_t xqc_wfsplit_scheduler_cb = {
    .xqc_scheduler_size              = xqc_wfsplit_scheduler_size,
    .xqc_scheduler_init              = xqc_wfsplit_scheduler_init,
    .xqc_scheduler_get_path          = xqc_wfsplit_scheduler_get_path,
    .xqc_scheduler_handle_path_event = xqc_wfsplit_scheduler_handle_path_event,
    .xqc_scheduler_handle_conn_event = xqc_wfsplit_scheduler_handle_conn_event,
};
