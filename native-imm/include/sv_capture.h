/**
 * @file sv_capture.h
 * @brief Immediate-mode pcap capture wrapper for SV Ethernet frames
 *
 * Opens an interface via pcap_create with immediate mode enabled,
 * sets a BPF filter for EtherType 0x88BA, and polls packets one
 * at a time using pcap_next_ex.
 *
 * Immediate mode delivers each packet as soon as it arrives instead
 * of batching — lower latency at the cost of higher CPU usage.
 */

#ifndef SV_CAPTURE_H
#define SV_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Configuration ───────────────────────────────────────────────────────── */

#define SV_CAP_SNAPLEN      65536
#define SV_CAP_PROMISC      1
#define SV_CAP_TIMEOUT_MS   1   /* pcap read timeout */

/* ── Callback type ───────────────────────────────────────────────────────── */

/**
 * Called once per captured packet.
 *   buffer:    raw Ethernet frame
 *   length:    frame length in bytes
 *   ts_us:     pcap timestamp in microseconds since epoch
 *   user_data: opaque pointer passed to sv_capture_start()
 */
typedef void (*sv_packet_cb)(const uint8_t *buffer, size_t length,
                             uint64_t ts_us, void *user_data);

/* ── Opaque handle ───────────────────────────────────────────────────────── */

typedef struct SvCapture SvCapture;

/* ── API ─────────────────────────────────────────────────────────────────── */

/**
 * Open an interface for SV capture (immediate mode).
 * filter: optional BPF filter string (NULL → default "ether proto 0x88ba").
 * Returns handle on success, NULL on failure (errbuf filled).
 */
SvCapture *sv_capture_open(const char *interface_name,
                           const char *filter,
                           char *errbuf, size_t errbuf_len);

/**
 * Run the capture loop (blocking).
 * Uses pcap_next_ex to poll one packet at a time.
 * Calls cb for each packet. Returns when sv_capture_stop() is called
 * or pcap_next_ex returns an error.
 * Returns 0 on clean stop, -1 on error.
 */
int sv_capture_run(SvCapture *cap, sv_packet_cb cb, void *user_data);

/**
 * Break out of the capture loop (signal-safe).
 * Can be called from a signal handler.
 */
void sv_capture_stop(SvCapture *cap);

/**
 * Close the capture handle and free resources.
 */
void sv_capture_close(SvCapture *cap);

#ifdef __cplusplus
}
#endif

#endif /* SV_CAPTURE_H */
