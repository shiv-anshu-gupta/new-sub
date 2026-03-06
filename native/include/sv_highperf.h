/**
 * @file sv_highperf.h
 * @brief High-Performance Capture & Processing for 1 Gbps SV Traffic
 *
 * Designed to handle ~1,000,000 SV frames/sec (1 Gbps line rate).
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  Capture Thread (efficient — NO mutex, NO alloc)                   │
 * │  pcap_dispatch() callback → decode inline → write to SPSC ring    │
 * │  Target: < 1μs per packet                                          │
 * └─────────────────────┬───────────────────────────────────────────────┘
 *                       │ lock-free SPSC ring (1M slots)
 *                       ▼
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  Drain Thread (background — batch analysis + stats)                │
 * │  Reads SPSC ring → runs analysis → writes to display buffer       │
 * │  Runs every 50ms, processes up to 100K frames per batch            │
 * └─────────────────────┬───────────────────────────────────────────────┘
 *                       │ mutex-protected display buffer
 *                       ▼
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  Display Buffer (20K frames + sampled subset for JSON)            │
 * │  Frontend polls this via get_poll_json()                           │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Key metrics tracked:
 *   - Capture rate (pps)
 *   - Decode rate (pps)
 *   - Drop count (kernel + SPSC overflow)
 *   - Throughput (Mbps)
 */

#ifndef SV_HIGHPERF_H
#define SV_HIGHPERF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Configuration
 *============================================================================*/

/** SPSC ring buffer capacity — must be power of 2 for fast modulo.
 *  128K slots ≈ 9 sec at 14kHz, 1600 sec at 80Hz.
 *  sizeof(SvCompactFrame) × 128K ≈ 24 MB. */
#define SV_SPSC_CAPACITY        (1 << 17)   /* 131,072 */
#define SV_SPSC_MASK            (SV_SPSC_CAPACITY - 1)

/** Main display ring buffer — what the frontend reads from */
#define SV_DISPLAY_CAPACITY     5000

/** Drain thread batch size — how many frames to process per drain tick */
#define SV_DRAIN_BATCH_MAX      100000

/** Drain thread interval (ms) */
#define SV_DRAIN_INTERVAL_MS    25

/** Compact frame for SPSC — only essential fields, no strings, minimal size */
#define SV_COMPACT_MAX_CH       20

/*============================================================================
 * Compact Frame — Minimal struct for lock-free ring (hot path)
 * 
 * ~112 bytes vs ~800 bytes for SvDecodedFrame — 7x smaller = 7x more
 * cache-friendly in the SPSC ring.
 *============================================================================*/

typedef struct {
    uint16_t    smpCnt;
    uint32_t    confRev;
    uint8_t     smpSynch;
    uint8_t     channelCount;
    int32_t     values[SV_COMPACT_MAX_CH];      /* Channel values */
    uint32_t    quality[SV_COMPACT_MAX_CH];     /* Channel quality */
    uint32_t    errors;                          /* Combined frame+ASDU errors */
    uint64_t    timestamp_us;
    uint16_t    appID;
    uint8_t     svID_hash;                       /* FNV-1a hash of svID for fast filter */
    uint8_t     noASDU;                          /* Original noASDU from wire (1,2,4,8,16) */
    uint8_t     asduIndex;                       /* This ASDU's index within the frame (0-based) */
    /* svID stored separately in shared string table */
} SvCompactFrame;

/*============================================================================
 * High-perf capture stats
 *============================================================================*/

typedef struct {
    /* Capture layer */
    uint64_t    captureTotal;       /**< Total packets seen by pcap */
    uint64_t    captureSV;          /**< Packets matching SV EtherType */
    uint64_t    captureDropKernel;  /**< Packets dropped by kernel/driver */
    uint64_t    captureBytes;       /**< Total bytes captured */
    
    /* SPSC ring */
    uint64_t    spscWritten;        /**< Frames written to SPSC */
    uint64_t    spscDropped;        /**< Frames dropped (SPSC full) */
    uint64_t    spscReadLag;        /**< Current read lag (write - read) */
    
    /* Drain/analysis */
    uint64_t    drainTotal;         /**< Frames drained from SPSC */
    uint64_t    drainBatchAvg;      /**< Average batch size per drain tick */
    
    /* Rates (calculated) */
    double      captureRatePps;     /**< Current capture rate (packets/sec) */
    double      throughputMbps;     /**< Current throughput (Megabits/sec) */
    
    /* Timing */
    uint64_t    captureElapsedMs;
    uint8_t     isCapturing;
} SvHighPerfStats;

/*============================================================================
 * API — Called from sv_capture_impl.cc and sv_subscriber.cc
 *============================================================================*/

/**
 * @brief Initialize the high-perf pipeline
 * Must be called before capture starts.
 */
void sv_highperf_init(void);

/**
 * @brief Shut down and free resources
 */
void sv_highperf_shutdown(void);

/**
 * @brief Start the drain thread
 * Called after capture starts.
 */
void sv_highperf_start_drain(void);

/**
 * @brief Stop the drain thread
 * Called before capture stops.
 */
void sv_highperf_stop_drain(void);

/**
 * @brief Feed a decoded compact frame into the SPSC ring
 * 
 * Called from capture thread — MUST be lock-free.
 * Returns 0 on success, -1 if SPSC is full (frame dropped).
 */
int sv_highperf_push_frame(const SvCompactFrame *frame);

/**
 * @brief Quick inline decode + push (for capture thread hot path)
 * 
 * Decodes raw packet → compact frame → pushes to SPSC.
 * All in one call, no intermediate copies.
 *
 * @param buffer     Raw Ethernet frame
 * @param length     Packet length
 * @param ts_us      Capture timestamp (microseconds)
 * @return 0 on success, -1 on decode error, -2 on SPSC full
 */
int sv_highperf_capture_feed(const uint8_t *buffer, size_t length, uint64_t ts_us);

/**
 * @brief Get high-perf stats
 */
void sv_highperf_get_stats(SvHighPerfStats *stats);

/**
 * @brief Get high-perf stats as JSON (for frontend)
 */
const char* sv_highperf_get_stats_json(void);

#ifdef __cplusplus
}
#endif

#endif /* SV_HIGHPERF_H */
