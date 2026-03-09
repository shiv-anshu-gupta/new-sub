/**
 * @file sv_decoder.h
 * @brief IEC 61850-9-2LE Sampled Values Decoder
 *
 * Decodes raw Ethernet frames containing SV packets into structured data.
 * Single, clean decoder — no duplication.
 */

#ifndef SV_DECODER_H
#define SV_DECODER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ───────────────────────────────────────────────────────────── */

#define SV_MAX_CHANNELS     20
#define SV_MAX_ASDUS        16
#define SV_MAX_SVID_LEN     64
#define SV_ETHERTYPE        0x88BA
#define SV_VLAN_ETHERTYPE   0x8100

/* ── Error bitmask ───────────────────────────────────────────────────────── */

#define SV_ERR_NONE                 0x00000000
#define SV_ERR_BUFFER_TOO_SHORT     0x00000001
#define SV_ERR_WRONG_ETHERTYPE      0x00000002
#define SV_ERR_INVALID_SV_LENGTH    0x00000004
#define SV_ERR_BER_DECODE_FAIL      0x00000008
#define SV_ERR_MISSING_SAVPDU       0x00000010
#define SV_ERR_MISSING_NOASDU       0x00000020
#define SV_ERR_MISSING_SEQASDU      0x00000040
#define SV_ERR_MISSING_SVID         0x00000080
#define SV_ERR_ASDU_COUNT_MISMATCH  0x00000800
#define SV_ERR_CHANNEL_DATA_SHORT   0x00001000

/* ── Data structures ─────────────────────────────────────────────────────── */

/** Ethernet + SV header fields */
typedef struct {
    uint8_t     dst_mac[6];
    uint8_t     src_mac[6];
    uint16_t    vlan_id;
    uint8_t     vlan_priority;
    uint8_t     has_vlan;
    uint16_t    ether_type;
    uint16_t    app_id;
    uint16_t    sv_length;
} SvFrameHeader;

/** Single ASDU within an SV packet */
typedef struct {
    char        sv_id[SV_MAX_SVID_LEN + 1];
    uint16_t    smp_cnt;
    uint32_t    conf_rev;
    uint8_t     smp_synch;
    uint16_t    smp_rate;
    uint8_t     has_smp_rate;
    int32_t     values[SV_MAX_CHANNELS];
    uint32_t    quality[SV_MAX_CHANNELS];
    uint8_t     channel_count;
    uint32_t    errors;
} SvAsdu;

/** Complete decoded SV frame */
typedef struct {
    SvFrameHeader   header;
    uint8_t         no_asdu;
    uint8_t         asdu_count;
    SvAsdu          asdus[SV_MAX_ASDUS];
    uint32_t        errors;
    size_t          raw_length;
    uint64_t        timestamp_us;
} SvDecodedFrame;

/* ── API ─────────────────────────────────────────────────────────────────── */

/**
 * Decode a raw Ethernet frame into an SvDecodedFrame.
 * Returns 0 on success, -1 on fatal error.
 * Non-fatal errors are recorded in frame->errors.
 */
int sv_decode_frame(const uint8_t *buffer, size_t length, SvDecodedFrame *frame);

/** Human-readable string for a single SV_ERR_* bit */
const char *sv_error_string(uint32_t error_bit);

/** Format MAC address as "XX:XX:XX:XX:XX:XX" */
void sv_format_mac(const uint8_t *mac, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SV_DECODER_H */
