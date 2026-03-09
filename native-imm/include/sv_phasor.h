/**
 * @file sv_phasor.h
 * @brief DFT-based phasor estimation for SV channel data
 *
 * Computes magnitude + phase angle from buffered samples using
 * a simple DFT at the fundamental frequency bin.
 *
 * Optionally uses Intel MKL for FFT when ENABLE_MKL is defined.
 * Falls back to a direct Goertzel single-bin DFT otherwise.
 *
 * Build with: -DENABLE_PHASOR to include this module.
 */

#ifndef SV_PHASOR_H
#define SV_PHASOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ───────────────────────────────────────────────────────────── */

#define PHASOR_MAX_CHANNELS     20
#define PHASOR_MAX_WINDOW       256

/* ── Data structures ─────────────────────────────────────────────────────── */

typedef struct {
    double magnitude;       /**< Peak magnitude */
    double angle_deg;       /**< Phase angle in degrees (-180..+180) */
} SvPhasorValue;

typedef struct {
    SvPhasorValue channels[PHASOR_MAX_CHANNELS];
    uint8_t     channel_count;
    uint8_t     valid;          /**< 1 when result is ready */
    uint32_t    window_size;
    uint64_t    timestamp_us;
} SvPhasorResult;

/* Opaque engine handle */
typedef struct SvPhasorEngine SvPhasorEngine;

/* ── API ─────────────────────────────────────────────────────────────────── */

/**
 * Create a phasor engine.
 * samples_per_cycle: e.g. 80 for 4800 smp/s @ 60 Hz.
 * max_channels:      how many channels to process.
 * Returns NULL on failure.
 */
SvPhasorEngine *sv_phasor_create(uint16_t samples_per_cycle, uint8_t max_channels);

/**
 * Feed one sample (all channels).
 * Returns 1 if a new result was computed, 0 if still buffering, -1 on error.
 */
int sv_phasor_feed(SvPhasorEngine *eng, const int32_t *values,
                   uint8_t channel_count, uint64_t timestamp_us);

/** Get latest result (valid until next computation). */
const SvPhasorResult *sv_phasor_result(const SvPhasorEngine *eng);

/** Reset buffers, keep configuration. */
void sv_phasor_reset(SvPhasorEngine *eng);

/** Destroy engine and free resources. */
void sv_phasor_destroy(SvPhasorEngine *eng);

#ifdef __cplusplus
}
#endif

#endif /* SV_PHASOR_H */
