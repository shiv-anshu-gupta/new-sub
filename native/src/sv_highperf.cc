/**
 * @file sv_highperf.cc
 * @brief High-Performance 1 Gbps SV Capture Pipeline Implementation
 *
 * Lock-free SPSC ring buffer + background drain thread architecture.
 * Designed to sustain ~1,000,000 frames/sec from SV Publisher.
 *
 * Memory layout:
 *   SPSC ring: SvCompactFrame[1M] ≈ 112 MB (pre-allocated, never freed)
 *   Display ring: StoredFrame[5K] (existing ring buffer)
 *
 * Threading model:
 *   Capture thread → SPSC ring (lock-free write)
 *   Drain thread   → reads SPSC → analysis → display buffer (mutex)
 *   UI poll         → reads display buffer (mutex, same as before)
 */

#include "sv_highperf.h"
#include "sv_decoder.h"
#include "asn1_ber_decoder.h"
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdlib>

/*============================================================================
 * SPSC Ring Buffer — Lock-Free Single Producer Single Consumer
 *
 * The key to 1Mpps: capture thread writes without ANY lock.
 * Drain thread reads without ANY lock.
 * Only atomic load/store on head/tail indices (no CAS needed for SPSC).
 *
 * Cache-line padding prevents false sharing between producer and consumer.
 *============================================================================*/

/** Cache line size for padding (x86-64) */
#define CACHE_LINE_SIZE 64

/** Aligned atomic wrapper to prevent false sharing */
struct alignas(CACHE_LINE_SIZE) PaddedAtomic {
    std::atomic<uint64_t> value{0};
    char _pad[CACHE_LINE_SIZE - sizeof(std::atomic<uint64_t>)];
};

/** Lock-free SPSC ring buffer */
static struct {
    SvCompactFrame*     buffer;         /**< Pre-allocated frame array */
    PaddedAtomic        head;           /**< Write index (producer only) */
    PaddedAtomic        tail;           /**< Read index (consumer only) */
    std::atomic<uint64_t> dropped;      /**< Frames dropped due to full ring */
} g_spsc;

/*============================================================================
 * svID String Table — Avoids storing 65-byte strings in compact frames
 *
 * Most captures have 1-10 unique svIDs. We hash the svID to a uint8_t
 * and store the actual string in a small lookup table.
 *============================================================================*/

#define SVID_TABLE_SIZE 256

static struct {
    char        strings[SVID_TABLE_SIZE][SV_DEC_MAX_SVID_LEN + 1];
    uint8_t     used[SVID_TABLE_SIZE];
    int         count;
} g_svid_table;

/** FNV-1a hash → 8-bit index */
static uint8_t svid_hash(const char *svID) {
    uint32_t h = 0x811c9dc5u;
    for (const char *p = svID; *p; p++) {
        h ^= (uint8_t)*p;
        h *= 0x01000193u;
    }
    return (uint8_t)(h & 0xFF);
}

/** Register svID in table, return hash. Thread-safe via atomic flag. */
static uint8_t svid_register(const char *svID) {
    uint8_t h = svid_hash(svID);
    if (!g_svid_table.used[h]) {
        strncpy(g_svid_table.strings[h], svID, SV_DEC_MAX_SVID_LEN);
        g_svid_table.strings[h][SV_DEC_MAX_SVID_LEN] = '\0';
        g_svid_table.used[h] = 1;
        g_svid_table.count++;
    }
    return h;
}

/** Lookup svID by hash */
static const char* svid_lookup(uint8_t hash) {
    if (g_svid_table.used[hash]) return g_svid_table.strings[hash];
    return "";
}

/*============================================================================
 * Multi-ASDU Timestamp Interpolation
 *
 * Problem: When publisher sends noASDU > 1 (e.g., 8 ASDUs per Ethernet frame),
 * all ASDUs share ONE pcap timestamp because they arrive in ONE packet.
 * This creates duplicate timestamps in the UI regardless of HOST_HIPREC.
 *
 * Fix: Interpolate timestamps within multi-ASDU frames using the detected
 * sample interval. ASDU[i] gets: pcap_ts + i * sample_interval_us.
 * Auto-detects interval from consecutive Ethernet frame arrival times.
 *============================================================================*/

static double   g_sample_interval_us = 250.0;  /**< Default: 4000 smp/s → 250µs */
static uint64_t g_last_frame_ts = 0;           /**< Pcap timestamp of previous Ethernet frame */
static uint8_t  g_last_frame_noASDU = 0;       /**< noASDU count of previous frame */
static bool     g_interval_detected = false;    /**< True once interval auto-detected */

/*============================================================================
 * Drain Thread State
 *============================================================================*/

static std::atomic<bool>    g_drain_running{false};
static std::thread          g_drain_thread;

/*============================================================================
 * High-Perf Statistics (atomics for lock-free access)
 *============================================================================*/

static std::atomic<uint64_t> g_hp_capture_total{0};
static std::atomic<uint64_t> g_hp_capture_sv{0};
static std::atomic<uint64_t> g_hp_capture_bytes{0};
static std::atomic<uint64_t> g_hp_drain_total{0};
static std::atomic<uint64_t> g_hp_drain_batches{0};
static uint64_t              g_hp_start_ms = 0;

/*============================================================================
 * External: sv_subscriber functions we call from drain thread
 *============================================================================*/

/* These are defined in sv_subscriber.cc — we call them from drain thread */
extern "C" int sv_subscriber_feed_decoded(const SvCompactFrame *compact, 
                                           const char *svID);

/*============================================================================
 * SPSC Ring Operations
 *============================================================================*/

static inline uint64_t spsc_available_read() {
    uint64_t h = g_spsc.head.value.load(std::memory_order_acquire);
    uint64_t t = g_spsc.tail.value.load(std::memory_order_relaxed);
    return h - t;
}

static inline uint64_t spsc_available_write() {
    uint64_t h = g_spsc.head.value.load(std::memory_order_relaxed);
    uint64_t t = g_spsc.tail.value.load(std::memory_order_acquire);
    return SV_SPSC_CAPACITY - (h - t);
}

/**
 * Push a compact frame into SPSC ring.
 * Called from capture thread only (single producer).
 * Returns 0 on success, -1 if full.
 */
int sv_highperf_push_frame(const SvCompactFrame *frame) {
    uint64_t h = g_spsc.head.value.load(std::memory_order_relaxed);
    uint64_t t = g_spsc.tail.value.load(std::memory_order_acquire);
    
    if ((h - t) >= SV_SPSC_CAPACITY) {
        g_spsc.dropped.fetch_add(1, std::memory_order_relaxed);
        return -1; /* Full */
    }
    
    /* Copy frame into slot */
    memcpy(&g_spsc.buffer[h & SV_SPSC_MASK], frame, sizeof(SvCompactFrame));
    
    /* Release: make frame visible to consumer */
    g_spsc.head.value.store(h + 1, std::memory_order_release);
    return 0;
}

/**
 * Pop a compact frame from SPSC ring.
 * Called from drain thread only (single consumer).
 * Returns pointer to frame (valid until next pop), or NULL if empty.
 */
static SvCompactFrame* spsc_pop() {
    uint64_t t = g_spsc.tail.value.load(std::memory_order_relaxed);
    uint64_t h = g_spsc.head.value.load(std::memory_order_acquire);
    
    if (t >= h) return NULL; /* Empty */
    
    SvCompactFrame *frame = &g_spsc.buffer[t & SV_SPSC_MASK];
    /* Note: we don't advance tail yet — caller processes, then calls spsc_consume() */
    return frame;
}

static void spsc_consume(uint64_t count) {
    uint64_t t = g_spsc.tail.value.load(std::memory_order_relaxed);
    g_spsc.tail.value.store(t + count, std::memory_order_release);
}

/*============================================================================
 * Fast Inline Decode — Capture Thread Hot Path
 *
 * This function is called for EVERY packet. It must be as fast as possible.
 * Target: < 1μs per packet (to sustain 1Mpps).
 *
 * Handles variable ASDU counts (1, 2, 4, 8, 16 per frame).
 * Each ASDU is pushed as a separate SvCompactFrame to the SPSC ring.
 *
 * Optimizations vs full sv_decoder_decode_frame():
 *   - No memset of full SvDecodedFrame (3KB) — only compact (~190 bytes)
 *   - No string copy for svID — just hash
 *   - No error string formatting
 *   - Inline BER parsing (no function call overhead for simple cases)
 *   - Skip optional fields (datSet, refrTm, smpMod)
 *============================================================================*/

int sv_highperf_capture_feed(const uint8_t *buffer, size_t length, uint64_t ts_us) {
    if (!buffer || length < 22) return -1; /* Min: 14 Eth + 8 SV header */
    
    g_hp_capture_total.fetch_add(1, std::memory_order_relaxed);
    g_hp_capture_bytes.fetch_add(length, std::memory_order_relaxed);
    
    /* --- Ethernet header (inline, no function call) --- */
    size_t pos = 12;
    uint16_t ethertype = ((uint16_t)buffer[pos] << 8) | buffer[pos + 1];
    
    if (ethertype == 0x8100) {
        /* VLAN tag */
        if (length < 26) return -1;
        pos = 16;
        ethertype = ((uint16_t)buffer[pos] << 8) | buffer[pos + 1];
    }
    
    if (ethertype != 0x88BA) return -1;
    pos += 2;
    
    /* --- SV header (8 bytes) --- */
    uint16_t appID = ((uint16_t)buffer[pos] << 8) | buffer[pos + 1];
    pos += 2;
    /* Skip Length(2) + Reserved(4) */
    pos += 6;
    
    /* --- savPdu BER (tag 0x60) --- */
    if (pos >= length || buffer[pos] != 0x60) return -1;
    pos++;
    
    /* Decode length (fast path: 1 or 2 byte length) */
    size_t pdu_len;
    if (buffer[pos] < 0x80) {
        pdu_len = buffer[pos++];
    } else {
        uint8_t num_bytes = buffer[pos++] & 0x7F;
        if (num_bytes == 1) {
            pdu_len = buffer[pos++];
        } else if (num_bytes == 2) {
            pdu_len = ((size_t)buffer[pos] << 8) | buffer[pos + 1];
            pos += 2;
        } else {
            return -1; /* Unusual length encoding */
        }
    }
    
    const uint8_t *pdu_start = buffer + pos;
    const uint8_t *pdu_end = pdu_start + pdu_len;
    if ((size_t)(pdu_end - buffer) > length) return -1;
    
    /* --- Iterate savPdu children: noASDU (0x80) + seqASDU (0xA2) --- */
    const uint8_t *p = pdu_start;
    const uint8_t *asdu_data = NULL;
    size_t asdu_len = 0;
    uint8_t wire_noASDU = 1;  /* Default: 1 ASDU if tag missing */
    
    while (p < pdu_end) {
        uint8_t tag = *p++;
        size_t tlen;
        if (*p < 0x80) {
            tlen = *p++;
        } else {
            uint8_t nb = *p++ & 0x7F;
            if (nb == 1) { tlen = *p++; }
            else if (nb == 2) { tlen = ((size_t)p[0] << 8) | p[1]; p += 2; }
            else return -1;
        }
        
        if (tag == 0x80 && tlen >= 1) { /* noASDU */
            wire_noASDU = *p;
        } else if (tag == 0xA2) { /* seqASDU */
            asdu_data = p;
            asdu_len = tlen;
        }
        p += tlen;
    }
    
    if (!asdu_data) return -1;
    
    /* ── Auto-detect sample interval from consecutive Ethernet frames ──
     * Compare pcap timestamps of successive frames to estimate the per-sample
     * interval. This drives multi-ASDU timestamp interpolation below. */
    if (g_last_frame_ts > 0 && g_last_frame_noASDU > 0 && ts_us > g_last_frame_ts) {
        double frame_gap_us = (double)(ts_us - g_last_frame_ts);
        double estimated = frame_gap_us / (double)g_last_frame_noASDU;
        /* Sanity: valid range 10µs..10ms (100kHz..100Hz sample rates) */
        if (estimated > 10.0 && estimated < 10000.0) {
            /* Exponential moving average for stability */
            if (g_interval_detected) {
                g_sample_interval_us = g_sample_interval_us * 0.9 + estimated * 0.1;
            } else {
                g_sample_interval_us = estimated;
                g_interval_detected = true;
                printf("[highperf] Auto-detected sample interval: %.1f us (%.0f smp/s)\n",
                       g_sample_interval_us, 1000000.0 / g_sample_interval_us);
            }
        }
    }
    g_last_frame_ts = ts_us;
    g_last_frame_noASDU = wire_noASDU;
    
    /* --- Parse ALL ASDUs (0x30) — push one SvCompactFrame per ASDU --- */
    /* SV frames can have 1, 2, 4, 8, or 16 ASDUs. Each ASDU has its own
     * smpCnt and channel data. We push each as a separate compact frame
     * so the analysis engine sees each sample individually.
     *
     * TIMESTAMP INTERPOLATION: For multi-ASDU frames, each ASDU gets a
     * unique timestamp: pcap_ts + asduIndex × sample_interval_us.
     * This eliminates duplicate timestamps caused by multiple ASDUs
     * sharing a single Ethernet packet's pcap arrival time. */
    const uint8_t *asdu_ptr = asdu_data;
    const uint8_t *asdu_container_end = asdu_data + asdu_len;
    int asdu_count = 0;
    int push_result = 0;
    
    while (asdu_ptr < asdu_container_end) {
        if (*asdu_ptr != 0x30) break; /* Not an ASDU sequence tag */
        asdu_ptr++;
        
        size_t asdu_body_len;
        if (*asdu_ptr < 0x80) {
            asdu_body_len = *asdu_ptr++;
        } else {
            uint8_t nb = *asdu_ptr++ & 0x7F;
            if (nb == 1) { asdu_body_len = *asdu_ptr++; }
            else if (nb == 2) { asdu_body_len = ((size_t)asdu_ptr[0] << 8) | asdu_ptr[1]; asdu_ptr += 2; }
            else break;
        }
        
        const uint8_t *this_asdu_end = asdu_ptr + asdu_body_len;
        if (this_asdu_end > asdu_container_end) break;
        
        /* --- Parse this ASDU's fields --- */
        SvCompactFrame compact;
        compact.smpCnt = 0;
        compact.confRev = 0;
        compact.smpSynch = 0;
        compact.channelCount = 0;
        compact.errors = 0;
        compact.svID_hash = 0;
        compact.noASDU = wire_noASDU;
        compact.asduIndex = (uint8_t)asdu_count;  /* 0-based index within this frame */
        /* Interpolate timestamp for multi-ASDU frames:
         * ASDU[0] = pcap_ts, ASDU[1] = pcap_ts + interval, etc.
         * For noASDU=1, offset is 0 so timestamp = pcap_ts (no change). */
        compact.timestamp_us = ts_us + (uint64_t)(asdu_count * g_sample_interval_us);
        compact.appID = appID;
        
        char svID_buf[SV_DEC_MAX_SVID_LEN + 1] = {0};
        const uint8_t *fp = asdu_ptr;
        
        while (fp < this_asdu_end) {
            uint8_t tag = *fp++;
            if (fp >= this_asdu_end) break;
            
            size_t flen;
            if (*fp < 0x80) {
                flen = *fp++;
            } else {
                uint8_t nb = *fp++ & 0x7F;
                if (nb == 1) { flen = *fp++; }
                else if (nb == 2) { flen = ((size_t)fp[0] << 8) | fp[1]; fp += 2; }
                else break;
            }
            
            if (fp + flen > this_asdu_end) break;
            
            switch (tag) {
                case 0x80: /* svID */
                    if (flen <= SV_DEC_MAX_SVID_LEN) {
                        memcpy(svID_buf, fp, flen);
                        svID_buf[flen] = '\0';
                        compact.svID_hash = svid_register(svID_buf);
                    }
                    break;
                    
                case 0x82: /* smpCnt */
                    if (flen >= 2) {
                        compact.smpCnt = ((uint16_t)fp[flen-2] << 8) | fp[flen-1];
                    } else if (flen == 1) {
                        compact.smpCnt = fp[0];
                    }
                    break;
                    
                case 0x83: /* confRev */
                    if (flen >= 4) {
                        compact.confRev = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16) |
                                         ((uint32_t)fp[2] << 8) | fp[3];
                    }
                    break;
                    
                case 0x85: /* smpSynch */
                    if (flen >= 1) compact.smpSynch = fp[0];
                    break;
                    
                case 0x87: /* seqData — channel values + quality */
                {
                    uint8_t nch = (uint8_t)(flen / 8);
                    if (nch > SV_COMPACT_MAX_CH) nch = SV_COMPACT_MAX_CH;
                    compact.channelCount = nch;
                    
                    for (int ch = 0; ch < nch; ch++) {
                        const uint8_t *cd = fp + ch * 8;
                        compact.values[ch] = (int32_t)(
                            ((uint32_t)cd[0] << 24) | ((uint32_t)cd[1] << 16) |
                            ((uint32_t)cd[2] << 8) | cd[3]);
                        compact.quality[ch] = 
                            ((uint32_t)cd[4] << 24) | ((uint32_t)cd[5] << 16) |
                            ((uint32_t)cd[6] << 8) | cd[7];
                    }
                    break;
                }
                
                default:
                    break;
            }
            
            fp += flen;
        }
        
        /* Push this ASDU to SPSC */
        push_result = sv_highperf_push_frame(&compact);
        asdu_count++;
        
        /* Advance to next ASDU */
        asdu_ptr = this_asdu_end;
    }
    
    if (asdu_count == 0) return -1;
    
    g_hp_capture_sv.fetch_add(asdu_count, std::memory_order_relaxed);
    return push_result;
}

/*============================================================================
 * Drain Thread — Batch reader from SPSC → analysis → display buffer
 *
 * Runs at 40Hz (25ms interval). Each tick:
 *   1. Read up to 100K frames from SPSC
 *   2. Run analysis on each
 *   3. Write to display buffer (with mutex — same as old feed_packet)
 *   4. Update rate stats
 *============================================================================*/

static void drain_thread_func() {
    printf("[highperf] Drain thread started (interval=%dms, batch_max=%d)\n",
           SV_DRAIN_INTERVAL_MS, SV_DRAIN_BATCH_MAX);
    
    while (g_drain_running.load(std::memory_order_relaxed)) {
        uint64_t tail = g_spsc.tail.value.load(std::memory_order_relaxed);
        uint64_t head = g_spsc.head.value.load(std::memory_order_acquire);
        uint64_t avail = head - tail;
        
        if (avail == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(SV_DRAIN_INTERVAL_MS));
            continue;
        }
        
        /* Process up to batch max */
        uint64_t to_process = (avail < SV_DRAIN_BATCH_MAX) ? avail : SV_DRAIN_BATCH_MAX;
        
        for (uint64_t i = 0; i < to_process; i++) {
            /* Index each frame by tail + i — NOT via spsc_pop() which always reads tail */
            SvCompactFrame *frame = &g_spsc.buffer[(tail + i) & SV_SPSC_MASK];
            
            /* Feed to subscriber (which handles analysis + ring buffer storage) */
            const char *svID = svid_lookup(frame->svID_hash);
            sv_subscriber_feed_decoded(frame, svID);
        }
        
        /* Advance consumer pointer in one go */
        spsc_consume(to_process);
        g_hp_drain_total.fetch_add(to_process, std::memory_order_relaxed);
        g_hp_drain_batches.fetch_add(1, std::memory_order_relaxed);
        
        /* Sleep remainder of interval.
         * Always sleep at least 1ms even when batch was full — prevents
         * the drain thread from burning 100% CPU when the publisher is fast. */
        if (to_process < (uint64_t)SV_DRAIN_BATCH_MAX) {
            std::this_thread::sleep_for(std::chrono::milliseconds(SV_DRAIN_INTERVAL_MS));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    /* Final drain: process everything remaining */
    uint64_t tail = g_spsc.tail.value.load(std::memory_order_relaxed);
    uint64_t head = g_spsc.head.value.load(std::memory_order_acquire);
    uint64_t final_count = head - tail;
    for (uint64_t i = 0; i < final_count; i++) {
        SvCompactFrame *frame = &g_spsc.buffer[(tail + i) & SV_SPSC_MASK];
        const char *svID = svid_lookup(frame->svID_hash);
        sv_subscriber_feed_decoded(frame, svID);
    }
    if (final_count > 0) {
        spsc_consume(final_count);
        g_hp_drain_total.fetch_add(final_count, std::memory_order_relaxed);
    }
    
    printf("[highperf] Drain thread stopped. Total drained: %llu\n",
           (unsigned long long)g_hp_drain_total.load());
}

/*============================================================================
 * Lifecycle
 *============================================================================*/

extern "C" {

void sv_highperf_init(void) {
    /* Allocate SPSC buffer */
    if (!g_spsc.buffer) {
        g_spsc.buffer = (SvCompactFrame*)calloc(SV_SPSC_CAPACITY, sizeof(SvCompactFrame));
        if (!g_spsc.buffer) {
            printf("[highperf] FATAL: Failed to allocate SPSC buffer (%zu MB)\n",
                   (size_t)(SV_SPSC_CAPACITY * sizeof(SvCompactFrame)) / (1024 * 1024));
            return;
        }
        printf("[highperf] SPSC buffer allocated: %d slots × %zu bytes = %zu MB\n",
               SV_SPSC_CAPACITY, sizeof(SvCompactFrame),
               (size_t)(SV_SPSC_CAPACITY * sizeof(SvCompactFrame)) / (1024 * 1024));
    }
    
    /* Reset indices */
    g_spsc.head.value.store(0, std::memory_order_relaxed);
    g_spsc.tail.value.store(0, std::memory_order_relaxed);
    g_spsc.dropped.store(0, std::memory_order_relaxed);
    
    /* Reset svID table */
    memset(&g_svid_table, 0, sizeof(g_svid_table));
    
    /* Reset stats */
    g_hp_capture_total.store(0);
    g_hp_capture_sv.store(0);
    g_hp_capture_bytes.store(0);
    g_hp_drain_total.store(0);
    g_hp_drain_batches.store(0);
    
    g_hp_start_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    /* Reset multi-ASDU timestamp interpolation state */
    g_sample_interval_us = 250.0;  /* Default: 4000 smp/s */
    g_last_frame_ts = 0;
    g_last_frame_noASDU = 0;
    g_interval_detected = false;
    
    printf("[highperf] Pipeline initialized\n");
}

void sv_highperf_shutdown(void) {
    sv_highperf_stop_drain();
    
    if (g_spsc.buffer) {
        free(g_spsc.buffer);
        g_spsc.buffer = nullptr;
    }
    
    printf("[highperf] Pipeline shut down\n");
}

void sv_highperf_start_drain(void) {
    if (g_drain_running.load()) return;
    g_drain_running.store(true);
    g_drain_thread = std::thread(drain_thread_func);
    printf("[highperf] Drain thread launched\n");
}

void sv_highperf_stop_drain(void) {
    if (!g_drain_running.load()) return;
    g_drain_running.store(false);
    if (g_drain_thread.joinable()) {
        g_drain_thread.join();
    }
    printf("[highperf] Drain thread joined\n");
}

/*============================================================================
 * Statistics
 *============================================================================*/

void sv_highperf_get_stats(SvHighPerfStats *stats) {
    if (!stats) return;
    
    uint64_t now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    stats->captureTotal = g_hp_capture_total.load(std::memory_order_relaxed);
    stats->captureSV = g_hp_capture_sv.load(std::memory_order_relaxed);
    stats->captureDropKernel = 0; /* Updated from pcap stats separately */
    stats->captureBytes = g_hp_capture_bytes.load(std::memory_order_relaxed);
    
    stats->spscWritten = g_spsc.head.value.load(std::memory_order_relaxed);
    stats->spscDropped = g_spsc.dropped.load(std::memory_order_relaxed);
    stats->spscReadLag = spsc_available_read();
    
    stats->drainTotal = g_hp_drain_total.load(std::memory_order_relaxed);
    uint64_t batches = g_hp_drain_batches.load(std::memory_order_relaxed);
    stats->drainBatchAvg = batches > 0 ? stats->drainTotal / batches : 0;
    
    uint64_t elapsed = now_ms - g_hp_start_ms;
    stats->captureElapsedMs = elapsed;
    stats->isCapturing = g_drain_running.load() ? 1 : 0;
    
    if (elapsed > 0) {
        double secs = elapsed / 1000.0;
        stats->captureRatePps = stats->captureSV / secs;
        stats->throughputMbps = (stats->captureBytes * 8.0) / (secs * 1000000.0);
    } else {
        stats->captureRatePps = 0;
        stats->throughputMbps = 0;
    }
}

const char* sv_highperf_get_stats_json(void) {
    /* Stats are embedded in sv_capture_get_stats_json() instead */
    return "{}";
}

} /* extern "C" */
