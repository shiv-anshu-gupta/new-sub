/**
 * @file sv_phasor.cc
 * @brief Phasor estimation via Goertzel algorithm (no MKL dependency).
 *
 * When ENABLE_MKL is defined, uses Intel MKL FFT instead.
 * Otherwise, uses a single-bin Goertzel DFT for the fundamental — fast,
 * dependency-free, and perfectly accurate for phasor extraction.
 *
 * Build: compiled only when -DENABLE_PHASOR is passed to CMake.
 */

#include "sv_phasor.h"
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdio>

#ifdef ENABLE_MKL
#include <mkl_dfti.h>
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ── Internal engine state ───────────────────────────────────────────────── */

struct SvPhasorEngine {
    uint16_t    samples_per_cycle;
    uint8_t     max_channels;

    /* per-channel ring buffer: [channel][sample] */
    double      buf[PHASOR_MAX_CHANNELS][PHASOR_MAX_WINDOW];
    uint32_t    buf_pos;

    SvPhasorResult result;

#ifdef ENABLE_MKL
    DFTI_DESCRIPTOR_HANDLE fft_handle;
    double      fft_work[2 * PHASOR_MAX_WINDOW]; /* complex interleaved */
#endif
};

/* ── Goertzel single-bin DFT ─────────────────────────────────────────────── */

#ifndef ENABLE_MKL
/**
 * Compute magnitude and phase of bin k in a length-N real signal.
 * For the fundamental: k = 1.
 */
static void goertzel(const double *x, uint32_t N, uint32_t k,
                     double *mag, double *angle_deg)
{
    double w = 2.0 * M_PI * k / N;
    double coeff = 2.0 * std::cos(w);
    double s0 = 0.0, s1 = 0.0, s2 = 0.0;

    for (uint32_t i = 0; i < N; ++i) {
        s0 = x[i] + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
    }

    double re = s1 - s2 * std::cos(w);
    double im = s2 * std::sin(w);

    double raw = std::sqrt(re * re + im * im);
    *mag       = 2.0 * raw / N;
    *angle_deg = std::atan2(im, re) * (180.0 / M_PI);
}
#endif

/* ── Compute phasors for all channels ────────────────────────────────────── */

static void compute(SvPhasorEngine *eng)
{
    uint32_t N   = eng->samples_per_cycle;
    uint8_t  nch = eng->max_channels;

#ifdef ENABLE_MKL
    for (uint8_t ch = 0; ch < nch; ++ch) {
        for (uint32_t i = 0; i < N; ++i) {
            eng->fft_work[2 * i]     = eng->buf[ch][i];
            eng->fft_work[2 * i + 1] = 0.0;
        }
        MKL_LONG st = DftiComputeForward(eng->fft_handle, eng->fft_work);
        if (st != DFTI_NO_ERROR) {
            eng->result.channels[ch] = {0.0, 0.0};
            continue;
        }
        double re = eng->fft_work[2];
        double im = eng->fft_work[3];
        double raw = std::sqrt(re * re + im * im);
        eng->result.channels[ch].magnitude = 2.0 * raw / N;
        eng->result.channels[ch].angle_deg = std::atan2(im, re) * (180.0 / M_PI);
    }
#else
    for (uint8_t ch = 0; ch < nch; ++ch) {
        goertzel(eng->buf[ch], N, 1,
                 &eng->result.channels[ch].magnitude,
                 &eng->result.channels[ch].angle_deg);
    }
#endif

    eng->result.channel_count = nch;
    eng->result.valid         = 1;
    eng->result.window_size   = N;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

SvPhasorEngine *sv_phasor_create(uint16_t samples_per_cycle, uint8_t max_channels)
{
    if (samples_per_cycle == 0 || samples_per_cycle > PHASOR_MAX_WINDOW) return nullptr;
    if (max_channels > PHASOR_MAX_CHANNELS) max_channels = PHASOR_MAX_CHANNELS;

    auto *eng = static_cast<SvPhasorEngine *>(std::calloc(1, sizeof(SvPhasorEngine)));
    if (!eng) return nullptr;

    eng->samples_per_cycle = samples_per_cycle;
    eng->max_channels      = max_channels;

#ifdef ENABLE_MKL
    MKL_LONG N = samples_per_cycle;
    if (DftiCreateDescriptor(&eng->fft_handle, DFTI_DOUBLE, DFTI_COMPLEX, 1, N) != DFTI_NO_ERROR ||
        DftiCommitDescriptor(eng->fft_handle) != DFTI_NO_ERROR) {
        std::fprintf(stderr, "[phasor] MKL FFT init failed\n");
        std::free(eng);
        return nullptr;
    }
#endif

    return eng;
}

int sv_phasor_feed(SvPhasorEngine *eng, const int32_t *values,
                   uint8_t channel_count, uint64_t timestamp_us)
{
    if (!eng || !values) return -1;

    uint8_t nch = channel_count < eng->max_channels ? channel_count : eng->max_channels;

    for (uint8_t ch = 0; ch < nch; ++ch)
        eng->buf[ch][eng->buf_pos] = static_cast<double>(values[ch]);
    for (uint8_t ch = nch; ch < eng->max_channels; ++ch)
        eng->buf[ch][eng->buf_pos] = 0.0;

    eng->buf_pos++;
    eng->result.timestamp_us = timestamp_us;

    if (eng->buf_pos >= eng->samples_per_cycle) {
        compute(eng);
        eng->buf_pos = 0;
        return 1;
    }
    return 0;
}

const SvPhasorResult *sv_phasor_result(const SvPhasorEngine *eng)
{
    return eng ? &eng->result : nullptr;
}

void sv_phasor_reset(SvPhasorEngine *eng)
{
    if (!eng) return;
    eng->buf_pos = 0;
    std::memset(eng->buf, 0, sizeof(eng->buf));
    std::memset(&eng->result, 0, sizeof(eng->result));
}

void sv_phasor_destroy(SvPhasorEngine *eng)
{
    if (!eng) return;
#ifdef ENABLE_MKL
    if (eng->fft_handle) DftiFreeDescriptor(&eng->fft_handle);
#endif
    std::free(eng);
}
