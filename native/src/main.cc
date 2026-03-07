/**
 * @file main.cc
 * @brief SV Subscriber — standalone terminal application
 *
 * Usage:
 *   ./sv_subscriber --interface eth0 [--filter "ether proto 0x88ba"] [--csv output.csv]
 *
 * Captures IEC 61850 Sampled Values from the network, decodes them,
 * and prints one line per sample to stdout (or CSV file).
 * Ctrl+C to stop gracefully.
 */

#include "sv_capture.h"
#include "sv_decoder.h"

#ifdef ENABLE_PHASOR
#include "sv_phasor.h"
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <mutex>
#include <cinttypes>

/* ── Global state (minimal) ──────────────────────────────────────────────── */

static SvCapture   *g_cap = nullptr;
static FILE        *g_csv = nullptr;
static std::mutex   g_out_mtx;
static uint64_t     g_frame_count = 0;

#ifdef ENABLE_PHASOR
static SvPhasorEngine *g_phasor = nullptr;
#endif

/* ── Signal handler ──────────────────────────────────────────────────────── */

static void on_sigint(int)
{
    sv_capture_stop(g_cap);
}

/* ── Packet callback ─────────────────────────────────────────────────────── */

static void on_packet(const uint8_t *buffer, size_t length,
                      uint64_t ts_us, void * /*user*/)
{
    SvDecodedFrame frame;
    if (sv_decode_frame(buffer, length, &frame) != 0)
        return;

    std::lock_guard<std::mutex> lock(g_out_mtx);

    for (uint8_t i = 0; i < frame.asdu_count; ++i) {
        const SvAsdu *a = &frame.asdus[i];

        char mac_src[18], mac_dst[18];
        sv_format_mac(frame.header.src_mac, mac_src, sizeof(mac_src));
        sv_format_mac(frame.header.dst_mac, mac_dst, sizeof(mac_dst));

        /* stdout: one-liner per ASDU */
        std::printf("%" PRIu64 " | %s -> %s | appID=0x%04X | svID=%-16s "
                    "| smpCnt=%5u | confRev=%u | ch=%u |",
                    ts_us, mac_src, mac_dst,
                    frame.header.app_id, a->sv_id,
                    a->smp_cnt, a->conf_rev, a->channel_count);

        for (uint8_t ch = 0; ch < a->channel_count; ++ch)
            std::printf(" %d", a->values[ch]);
        std::putchar('\n');

        /* CSV output */
        if (g_csv) {
            std::fprintf(g_csv, "%" PRIu64 ",%s,%u,%u,%u,%u",
                         ts_us, a->sv_id, a->smp_cnt, a->conf_rev,
                         a->smp_synch, a->channel_count);
            for (uint8_t ch = 0; ch < a->channel_count; ++ch)
                std::fprintf(g_csv, ",%d,%u", a->values[ch], a->quality[ch]);
            std::fputc('\n', g_csv);
        }

#ifdef ENABLE_PHASOR
        if (g_phasor) {
            int rc = sv_phasor_feed(g_phasor, a->values, a->channel_count, ts_us);
            if (rc == 1) {
                const SvPhasorResult *pr = sv_phasor_result(g_phasor);
                std::printf("  [phasor] ");
                for (uint8_t ch = 0; ch < pr->channel_count; ++ch)
                    std::printf("ch%u: %.2f∠%.1f°  ", ch,
                                pr->channels[ch].magnitude,
                                pr->channels[ch].angle_deg);
                std::putchar('\n');
            }
        }
#endif

        ++g_frame_count;
    }
}

/* ── CLI parsing ─────────────────────────────────────────────────────────── */

struct Options {
    const char *interface_name;
    const char *filter;
    const char *csv_path;
    uint16_t    phasor_spc;     /* samples per cycle (0 = disabled) */
    uint8_t     phasor_ch;      /* channels for phasor (default 8) */
};

static void print_usage(const char *prog)
{
    std::fprintf(stderr,
        "Usage: %s --interface <name> [options]\n"
        "\n"
        "Options:\n"
        "  --interface <name>   Network interface (required)\n"
        "  --filter <bpf>       BPF filter (default: \"ether proto 0x88ba\")\n"
        "  --csv <path>         Write decoded samples to CSV file\n"
#ifdef ENABLE_PHASOR
        "  --phasor <spc>       Enable phasor (samples per cycle, e.g. 80)\n"
        "  --phasor-ch <n>      Phasor channel count (default 8)\n"
#endif
        "  --help               Show this help\n",
        prog);
}

static int parse_args(int argc, char **argv, Options *opts)
{
    std::memset(opts, 0, sizeof(*opts));
    opts->phasor_ch = 8;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--interface") == 0 && i + 1 < argc) {
            opts->interface_name = argv[++i];
        } else if (std::strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
            opts->filter = argv[++i];
        } else if (std::strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            opts->csv_path = argv[++i];
        }
#ifdef ENABLE_PHASOR
        else if (std::strcmp(argv[i], "--phasor") == 0 && i + 1 < argc) {
            opts->phasor_spc = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--phasor-ch") == 0 && i + 1 < argc) {
            opts->phasor_ch = static_cast<uint8_t>(std::atoi(argv[++i]));
        }
#endif
        else if (std::strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 1;
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    if (!opts->interface_name) {
        std::fprintf(stderr, "Error: --interface is required\n");
        print_usage(argv[0]);
        return -1;
    }
    return 0;
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    Options opts;
    int rc = parse_args(argc, argv, &opts);
    if (rc != 0) return rc < 0 ? 1 : 0;

    /* Open CSV if requested */
    if (opts.csv_path) {
        g_csv = std::fopen(opts.csv_path, "w");
        if (!g_csv) {
            std::fprintf(stderr, "Error: cannot open CSV file: %s\n", opts.csv_path);
            return 1;
        }
        /* CSV header */
        std::fprintf(g_csv, "timestamp_us,svID,smpCnt,confRev,smpSynch,channelCount");
        /* Dynamic channel columns written per-row since channel count may vary */
        std::fputc('\n', g_csv);
    }

#ifdef ENABLE_PHASOR
    if (opts.phasor_spc > 0) {
        g_phasor = sv_phasor_create(opts.phasor_spc, opts.phasor_ch);
        if (!g_phasor)
            std::fprintf(stderr, "Warning: phasor init failed, continuing without\n");
    }
#endif

    /* Open capture */
    char errbuf[256] = {};
    g_cap = sv_capture_open(opts.interface_name, opts.filter,
                            errbuf, sizeof(errbuf));
    if (!g_cap) {
        std::fprintf(stderr, "Error: %s\n", errbuf);
        if (g_csv) std::fclose(g_csv);
        return 1;
    }

    /* Install SIGINT handler for graceful shutdown */
    std::signal(SIGINT, on_sigint);
    std::signal(SIGTERM, on_sigint);

    std::fprintf(stderr, "Capturing SV on %s (Ctrl+C to stop)...\n",
                 opts.interface_name);

    /* Blocking capture loop — returns on SIGINT or error */
    rc = sv_capture_run(g_cap, on_packet, nullptr);

    /* Cleanup */
    sv_capture_close(g_cap);
    g_cap = nullptr;

#ifdef ENABLE_PHASOR
    if (g_phasor) sv_phasor_destroy(g_phasor);
#endif

    if (g_csv) std::fclose(g_csv);

    std::fprintf(stderr, "\nCaptured %" PRIu64 " samples.\n", g_frame_count);
    return rc == 0 ? 0 : 1;
}
