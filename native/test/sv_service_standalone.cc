/**
 * @file sv_service_standalone.cc
 * @brief Standalone SV Capture Service — Runs C++ backend WITHOUT Tauri
 *
 * Purpose: Isolate the C++ capture pipeline to measure its CPU usage
 * independently from Tauri/WebView. All output goes to a log file
 * so there's no frontend overhead at all.
 *
 * Build (Linux):
 *   g++ -std=c++17 -O3 -I../include \
 *       sv_service_standalone.cc \
 *       ../src/sv_capture_impl.cc \
 *       ../src/sv_highperf.cc \
 *       ../src/sv_subscriber.cc \
 *       ../src/sv_decoder_impl.cc \
 *       ../src/asn1_ber_decoder.cc \
 *       ../src/sv_phasor.cc \
 *       ../src/sv_phasor_csv.cc \
 *       -lpcap -lpthread \
 *       -I/opt/intel/oneapi/mkl/latest/include \
 *       -L/opt/intel/oneapi/mkl/latest/lib/intel64 \
 *       -lmkl_intel_lp64 -lmkl_sequential -lmkl_core -lm -ldl \
 *       -o sv_service_standalone
 *
 * Run:
 *   sudo setcap cap_net_raw,cap_net_admin=eip ./sv_service_standalone
 *   ./sv_service_standalone [interface_idx] [duration_seconds]
 *
 * Output:
 *   sv_service_log.txt — contains per-second stats + poll JSON dumps
 */

#include "../include/sv_capture.h"
#include "../include/sv_highperf.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <chrono>
#include <thread>
#include <unistd.h>  /* dup2 — redirect stdout to file */

/*============================================================================
 * Extern declarations — functions from the C++ backend
 *============================================================================*/
extern "C" {
    void        sv_subscriber_init(const char *svID, uint16_t smpCntMax);
    void        sv_subscriber_reset(void);
    const char* sv_subscriber_get_poll_json(uint32_t startIndex, uint32_t maxFrames);
    const char* sv_capture_get_stats_json(void);
    const char* sv_capture_get_timestamp_info_json(void);
}

/*============================================================================
 * Signal Handler
 *============================================================================*/
static volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    printf("\n[service] Ctrl+C — shutting down...\n");
    g_running = 0;
}

/*============================================================================
 * Main
 *============================================================================*/
int main(int argc, char *argv[]) {
    printf("============================================================\n");
    printf("  SV Standalone Service (NO Tauri)\n");
    printf("  Isolates C++ capture pipeline for CPU profiling\n");
    printf("============================================================\n");
    printf("  Usage: sv_service_standalone [iface_idx] [duration_sec]\n");
    printf("  Output: sv_service_log.txt\n");
    printf("============================================================\n\n");

    signal(SIGINT, signal_handler);

    /* ── Duration ── */
    int duration_sec = 0; /* 0 = run until Ctrl+C */
    if (argc > 2) duration_sec = atoi(argv[2]);

    /* ── Step 1: Load pcap (Linux: direct link, always returns 1) ── */
    printf("[1] Loading pcap...\n");
    if (!sv_capture_load_dll()) {
        printf("FATAL: %s\n", sv_capture_get_error());
        return 1;
    }
    printf("    OK\n\n");

    /* ── Step 2: List interfaces ── */
    printf("[2] Enumerating interfaces...\n");
    SvCaptureInterface interfaces[SV_CAP_MAX_INTERFACES];
    int count = sv_capture_list_interfaces(interfaces, SV_CAP_MAX_INTERFACES);
    if (count <= 0) {
        printf("FATAL: No interfaces. Need cap_net_raw or root.\n");
        return 1;
    }

    printf("\n    %-4s %-50s\n", "Idx", "Description / Name");
    printf("    %-4s %-50s\n", "---", "--------------------------------------------------");
    for (int i = 0; i < count; i++) {
        printf("    [%d]  %s\n", i,
               interfaces[i].description[0] ? interfaces[i].description : interfaces[i].name);
    }

    /* ── Step 3: Select interface ── */
    int selected = -1;
    if (argc > 1) {
        selected = atoi(argv[1]);
    } else {
        printf("\n    Enter interface index (0-%d): ", count - 1);
        fflush(stdout);
        if (scanf("%d", &selected) != 1) {
            printf("Invalid input\n");
            return 1;
        }
    }
    if (selected < 0 || selected >= count) {
        printf("FATAL: Invalid index %d\n", selected);
        return 1;
    }
    printf("    Selected: %s\n\n",
           interfaces[selected].description[0] ? interfaces[selected].description
                                                : interfaces[selected].name);

    /* ── Step 4: Init subscriber (auto-detect smpCntMax) ── */
    printf("[3] Initializing subscriber (auto-detect rate)...\n");
    sv_highperf_init();
    sv_subscriber_init("", 65535);  /* 65535 = auto-detect from wrap-around */
    printf("    OK\n\n");

    /* ── Step 5: Open interface ── */
    printf("[4] Opening interface...\n");
    if (sv_capture_open(interfaces[selected].name) != 0) {
        printf("FATAL: %s\n", sv_capture_get_error());
        return 1;
    }
    printf("    OK\n");

    /* Print timestamp config */
    const char *tsInfo = sv_capture_get_timestamp_info_json();
    printf("    Timestamp config: %s\n\n", tsInfo);

    /* ── Step 6: Open log file ── */
    const char *logpath = "sv_service_log.txt";
    FILE *logfp = fopen(logpath, "w");
    if (!logfp) {
        printf("FATAL: Cannot open %s for writing\n", logpath);
        sv_capture_close();
        return 1;
    }
    fprintf(logfp, "# SV Standalone Service Log\n");
    fprintf(logfp, "# Interface: %s\n",
            interfaces[selected].description[0] ? interfaces[selected].description
                                                 : interfaces[selected].name);
    fprintf(logfp, "# Timestamp: %s\n", tsInfo);
    fprintf(logfp, "# Timeout: %d ms, Buffer: %d bytes\n", SV_CAP_TIMEOUT_MS, SV_CAP_BUFFER_SIZE);
    fprintf(logfp, "#\n");
    fflush(logfp);

    /* ── Step 7: Start capture ── */
    printf("[5] Starting capture (pcap_dispatch mode, timeout=%d ms, buffer=%d MB)...\n",
           SV_CAP_TIMEOUT_MS, SV_CAP_BUFFER_SIZE / (1024*1024));
    if (sv_capture_start() != 0) {
        printf("FATAL: Failed to start capture\n");
        fclose(logfp);
        sv_capture_close();
        return 1;
    }
    printf("    OK — capture thread running\n\n");

    fprintf(stderr, "============================================================\n");
    fprintf(stderr, "  LISTENING on: %s\n",
           interfaces[selected].description[0] ? interfaces[selected].description
                                                : interfaces[selected].name);
    if (duration_sec > 0)
        fprintf(stderr, "  Duration: %d seconds\n", duration_sec);
    else
        fprintf(stderr, "  Duration: unlimited (Ctrl+C to stop)\n");
    fprintf(stderr, "  ALL output → %s  (zero console I/O during capture)\n", logpath);
    fprintf(stderr, "  Monitor CPU:  top -p $(pgrep sv_service)\n");
    fprintf(stderr, "============================================================\n\n");

    /* ── Redirect ALL stdout (including C++ backend printf) to log file ──
     * This eliminates ANY console I/O during capture so it cannot
     * contribute to CPU usage. Everything goes to the file. */
    fflush(stdout);
    if (dup2(fileno(logfp), STDOUT_FILENO) == -1) {
        perror("dup2 stdout→logfile failed");
    }

    /* ── Step 8: Monitor loop — ZERO console output ── */
    int seconds = 0;
    uint32_t lastFrameIdx = 0;
    uint64_t lastSV = 0;

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        seconds++;

        /* Check duration limit */
        if (duration_sec > 0 && seconds >= duration_sec) {
            fprintf(logfp, "[service] Duration limit reached (%d s), stopping.\n", duration_sec);
            break;
        }

        /* Get capture stats JSON */
        const char *statsJson = sv_capture_get_stats_json();

        /* Get poll JSON (up to 100 frames from where we left off) */
        const char *pollJson = sv_subscriber_get_poll_json(lastFrameIdx, 100);

        /* Get highperf stats */
        SvHighPerfStats hp;
        sv_highperf_get_stats(&hp);

        /* Compute delta rate */
        uint64_t curSV = hp.captureSV;
        uint64_t deltaSV = curSV - lastSV;
        lastSV = curSV;

        /* ALL output → log file only (no console) */
        fprintf(logfp, "\n===== t=%d s =====\n", seconds);
        fprintf(logfp, "SV: %llu | +%llu/s | Rate: %.0f pps | Drop: %llu | SPSC-lag: %llu | Throughput: %.2f Mbps\n",
               (unsigned long long)curSV,
               (unsigned long long)deltaSV,
               hp.captureRatePps,
               (unsigned long long)hp.spscDropped,
               (unsigned long long)hp.spscReadLag,
               hp.throughputMbps);
        fprintf(logfp, "capture_stats: %s\n", statsJson);
        fprintf(logfp, "highperf: captureTotal=%llu captureSV=%llu spscDropped=%llu spscLag=%llu "
                       "drainTotal=%llu ratePps=%.0f throughputMbps=%.2f\n",
                (unsigned long long)hp.captureTotal,
                (unsigned long long)hp.captureSV,
                (unsigned long long)hp.spscDropped,
                (unsigned long long)hp.spscReadLag,
                (unsigned long long)hp.drainTotal,
                hp.captureRatePps,
                hp.throughputMbps);
        fprintf(logfp, "poll_json: %s\n", pollJson ? pollJson : "null");
        fflush(logfp);

        /* Advance frame index (rough: use delta from last second) */
        lastFrameIdx += (uint32_t)deltaSV;
    }

    /* ── Cleanup ── */
    fprintf(logfp, "\n[service] Stopping capture...\n");
    sv_capture_stop();
    sv_capture_close();
    sv_highperf_shutdown();

    /* Final stats */
    fprintf(logfp, "\n===== FINAL =====\n");
    fprintf(logfp, "capture_stats: %s\n", sv_capture_get_stats_json());
    fflush(logfp);
    fclose(logfp);

    fprintf(stderr, "\n============================================================\n");
    fprintf(stderr, "  Capture Complete — %d seconds\n", seconds);
    fprintf(stderr, "  Log saved to: %s\n", logpath);
    fprintf(stderr, "============================================================\n");

    return 0;
}
