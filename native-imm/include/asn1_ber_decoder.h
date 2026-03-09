/**
 * @file asn1_ber_decoder.h
 * @brief ASN.1 BER TLV Decoder for IEC 61850 Sampled Values
 * 
 * This is the decoder counterpart to asn1_ber_encoder.cc.
 * It parses BER-encoded Tag-Length-Value structures used in SV packets.
 * 
 * Decoding Flow:
 * ┌─────────────────────────────────────┐
 * │  Raw Bytes                          │
 * │  60 xx 80 01 01 A2 xx 30 xx ...    │
 * └──────────────┬──────────────────────┘
 *                │ ber_decode_tlv()
 *                ▼
 * ┌─────────────────────────────────────┐
 * │  BerTLV { tag=0x60, len=xx,        │
 * │           value=ptr, value_len=xx } │
 * └──────────────┬──────────────────────┘
 *                │ iterate children
 *                ▼
 * ┌─────────────────────────────────────┐
 * │  Child TLVs: noASDU, seqASDU, ...  │
 * └─────────────────────────────────────┘
 */

#ifndef ASN1_BER_DECODER_H
#define ASN1_BER_DECODER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Tag Constants (same as encoder - reused for validation)
 *============================================================================*/

#define SV_DEC_TAG_SAVPDU       0x60  /* APPLICATION 0, CONSTRUCTED */
#define SV_DEC_TAG_NOASDU       0x80  /* context [0] IMPLICIT */
#define SV_DEC_TAG_SEQASDU      0xA2  /* context [2] CONSTRUCTED */
#define SV_DEC_TAG_ASDU         0x30  /* SEQUENCE */
#define SV_DEC_TAG_SVID         0x80  /* context [0] */
#define SV_DEC_TAG_DATSET       0x81  /* context [1] */
#define SV_DEC_TAG_SMPCNT       0x82  /* context [2] */
#define SV_DEC_TAG_CONFREV      0x83  /* context [3] */
#define SV_DEC_TAG_REFRTM       0x84  /* context [4] */
#define SV_DEC_TAG_SMPSYNCH     0x85  /* context [5] */
#define SV_DEC_TAG_SMPRATE      0x86  /* context [6] */
#define SV_DEC_TAG_SEQDATA      0x87  /* context [7] */
#define SV_DEC_TAG_SMPMOD       0x88  /* context [8] */

/*============================================================================
 * Error Codes
 *============================================================================*/

#define BER_OK                  0
#define BER_ERR_BUFFER_SHORT   -1   /* Not enough data to decode */
#define BER_ERR_INVALID_TAG    -2   /* Unexpected tag value */
#define BER_ERR_INVALID_LENGTH -3   /* Length field malformed or exceeds buffer */
#define BER_ERR_OVERFLOW       -4   /* Value exceeds expected size */

/*============================================================================
 * Decoded TLV Structure
 *============================================================================*/

/**
 * @brief Represents a decoded BER TLV element
 * 
 * After decoding, tag/length/value point into the original buffer.
 * No memory allocation needed.
 */
typedef struct {
    uint8_t     tag;            /**< Tag byte */
    size_t      length;         /**< Length of value */
    const uint8_t *value;       /**< Pointer to value data (into original buffer) */
    size_t      total_len;      /**< Total bytes consumed: tag + length_bytes + value */
    uint8_t     is_constructed; /**< 1 if tag is constructed (has children) */
} BerTLV;

/*============================================================================
 * Decoder Functions
 *============================================================================*/

/**
 * @brief Decode a BER tag byte
 * @param[in]  buf     Input buffer
 * @param[in]  buflen  Available bytes
 * @param[out] tag     Decoded tag value
 * @return Bytes consumed (1), or negative error code
 */
int ber_decode_tag(const uint8_t *buf, size_t buflen, uint8_t *tag);

/**
 * @brief Decode a BER length field
 * @param[in]  buf     Input buffer (starting at length byte)
 * @param[in]  buflen  Available bytes
 * @param[out] length  Decoded length value
 * @return Bytes consumed by length field (1-5), or negative error code
 */
int ber_decode_length(const uint8_t *buf, size_t buflen, size_t *length);

/**
 * @brief Decode a complete TLV structure
 * 
 * Parses tag + length + identifies value region. Does NOT recursively
 * decode children; call this again on value region for constructed types.
 * 
 * @param[in]  buf     Input buffer
 * @param[in]  buflen  Available bytes
 * @param[out] tlv     Decoded TLV result
 * @return BER_OK on success, negative error code on failure
 */
int ber_decode_tlv(const uint8_t *buf, size_t buflen, BerTLV *tlv);

/**
 * @brief Decode a BER-encoded unsigned integer value
 * @param[in]  data    Value bytes (from BerTLV.value)
 * @param[in]  len     Number of bytes (from BerTLV.length)
 * @param[out] result  Decoded unsigned value
 * @return BER_OK on success, negative error code on failure
 */
int ber_decode_unsigned(const uint8_t *data, size_t len, uint64_t *result);

/**
 * @brief Decode a BER-encoded signed integer value
 * @param[in]  data    Value bytes
 * @param[in]  len     Number of bytes
 * @param[out] result  Decoded signed value
 * @return BER_OK on success, negative error code on failure
 */
int ber_decode_signed(const uint8_t *data, size_t len, int64_t *result);

/**
 * @brief Decode a 32-bit big-endian signed integer (fixed 4 bytes)
 * Used for SV channel values
 */
int ber_decode_int32_be(const uint8_t *data, size_t len, int32_t *result);

/**
 * @brief Decode a 32-bit big-endian unsigned integer (fixed 4 bytes)
 * Used for SV quality flags
 */
int ber_decode_uint32_be(const uint8_t *data, size_t len, uint32_t *result);

/**
 * @brief Decode a 16-bit big-endian unsigned integer (fixed 2 bytes)
 * Used for smpCnt
 */
int ber_decode_uint16_be(const uint8_t *data, size_t len, uint16_t *result);

/**
 * @brief Iterate children of a constructed TLV
 * 
 * Call this repeatedly to walk through children of a SEQUENCE/SET/constructed tag.
 * 
 * @param[in]  parent_value     Parent's value buffer
 * @param[in]  parent_value_len Parent's value length
 * @param[in,out] offset        Current offset (start at 0, updated after each call)
 * @param[out] child            Next child TLV
 * @return BER_OK if child decoded, BER_ERR_BUFFER_SHORT when no more children
 */
int ber_decode_next_child(const uint8_t *parent_value, size_t parent_value_len,
                          size_t *offset, BerTLV *child);

#ifdef __cplusplus
}
#endif

#endif /* ASN1_BER_DECODER_H */
