/**
 * @file asn1_ber_decoder.cc
 * @brief ASN.1 BER TLV Decoder Implementation for IEC 61850 Sampled Values
 * 
 * This is the decoder counterpart to asn1_ber_encoder.cc.
 * It parses BER-encoded data structures from received SV packets.
 * 
 * @section decode_example Decoding Example
 * 
 * Given raw bytes from an SV savPdu:
 * ```
 * 60 1A                          ← savPdu tag=0x60, length=26
 *   80 01 01                     ← noASDU tag=0x80, length=1, value=1
 *   A2 15                        ← seqASDU tag=0xA2, length=21
 *     30 13                      ← ASDU tag=0x30, length=19
 *       80 04 4D 55 30 31        ← svID = "MU01"
 *       82 02 00 00              ← smpCnt = 0
 *       83 04 00 00 00 01        ← confRev = 1
 *       85 01 02                 ← smpSynch = 2
 *       87 08 ...                ← seqData = 1 channel × 8 bytes
 * ```
 * 
 * @section zero_copy Zero-Copy Design
 * 
 * The decoder uses zero-copy parsing: BerTLV.value points directly
 * into the input buffer. No memory allocation is performed.
 * The caller must keep the input buffer alive while using decoded results.
 */

#include "asn1_ber_decoder.h"
#include <string.h>

/*============================================================================
 * Tag Decoding
 *============================================================================*/

/**
 * @brief Decode a single-byte BER tag
 * 
 * IEC 61850 SV uses only single-byte tags, so we don't need
 * multi-byte tag support (high tag numbers > 30).
 * 
 * Tag byte structure:
 * ```
 * Bits 7-6: Class (00=Universal, 01=Application, 10=Context, 11=Private)
 * Bit  5:   Constructed (0=Primitive, 1=Constructed)
 * Bits 4-0: Tag number
 * ```
 */
int ber_decode_tag(const uint8_t *buf, size_t buflen, uint8_t *tag)
{
    if (!buf || !tag || buflen < 1) {
        return BER_ERR_BUFFER_SHORT;
    }
    *tag = buf[0];
    return 1; /* consumed 1 byte */
}

/*============================================================================
 * Length Decoding
 *============================================================================*/

/**
 * @brief Decode a BER length field
 * 
 * BER length encoding:
 * - Short form: 0x00-0x7F → length = byte value
 * - Long form:  0x81 → 1 byte follows
 *               0x82 → 2 bytes follow
 *               0x83 → 3 bytes follow
 *               0x84 → 4 bytes follow
 * 
 * Example:
 *   0x40         → length = 64
 *   0x81 0x80    → length = 128
 *   0x82 0x01 0x00 → length = 256
 */
int ber_decode_length(const uint8_t *buf, size_t buflen, size_t *length)
{
    if (!buf || !length || buflen < 1) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    uint8_t first = buf[0];
    
    /* Short form: bit 7 = 0, value is directly the length */
    if ((first & 0x80) == 0) {
        *length = first;
        return 1; /* consumed 1 byte */
    }
    
    /* Long form: lower 7 bits = number of subsequent length bytes */
    uint8_t numBytes = first & 0x7F;
    
    /* Indefinite length (0x80) - not used in SV, reject */
    if (numBytes == 0) {
        return BER_ERR_INVALID_LENGTH;
    }
    
    /* Sanity check: we support up to 4 length bytes */
    if (numBytes > 4) {
        return BER_ERR_INVALID_LENGTH;
    }
    
    /* Check we have enough data */
    if (buflen < (size_t)(1 + numBytes)) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    /* Decode big-endian length value */
    size_t val = 0;
    for (uint8_t i = 0; i < numBytes; i++) {
        val = (val << 8) | buf[1 + i];
    }
    
    *length = val;
    return 1 + numBytes; /* consumed: 1 (initial) + numBytes */
}

/*============================================================================
 * TLV Decoding
 *============================================================================*/

/**
 * @brief Decode a complete BER TLV structure
 * 
 * This function parses one TLV element from the buffer.
 * For constructed types (SEQUENCE, etc.), the value region contains
 * child TLVs that can be decoded with ber_decode_next_child().
 * 
 * @note Zero-copy: tlv->value points into the input buffer.
 */
int ber_decode_tlv(const uint8_t *buf, size_t buflen, BerTLV *tlv)
{
    if (!buf || !tlv || buflen < 2) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    size_t offset = 0;
    
    /* Decode tag */
    uint8_t tag;
    int tag_bytes = ber_decode_tag(buf + offset, buflen - offset, &tag);
    if (tag_bytes < 0) return tag_bytes;
    offset += (size_t)tag_bytes;
    
    /* Decode length */
    size_t value_len;
    int len_bytes = ber_decode_length(buf + offset, buflen - offset, &value_len);
    if (len_bytes < 0) return len_bytes;
    offset += (size_t)len_bytes;
    
    /* Validate: value must fit in remaining buffer */
    if (offset + value_len > buflen) {
        return BER_ERR_INVALID_LENGTH;
    }
    
    /* Fill result */
    tlv->tag = tag;
    tlv->length = value_len;
    tlv->value = buf + offset;
    tlv->total_len = offset + value_len;
    tlv->is_constructed = (tag & 0x20) ? 1 : 0;
    
    /* Special case: 0x60 (savPdu) and 0xA2 (seqASDU) are constructed
     * even though their bit patterns might confuse the check */
    if (tag == SV_DEC_TAG_SAVPDU || tag == SV_DEC_TAG_SEQASDU || tag == SV_DEC_TAG_ASDU) {
        tlv->is_constructed = 1;
    }
    
    return BER_OK;
}

/*============================================================================
 * Value Decoding Functions
 *============================================================================*/

/**
 * @brief Decode an unsigned integer from BER value bytes
 * 
 * BER integers use minimum bytes (DER rules).
 * A leading 0x00 byte is added when MSB is set (to keep it positive).
 */
int ber_decode_unsigned(const uint8_t *data, size_t len, uint64_t *result)
{
    if (!data || !result || len == 0) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    if (len > 8) {
        return BER_ERR_OVERFLOW;
    }
    
    uint64_t val = 0;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) | data[i];
    }
    
    *result = val;
    return BER_OK;
}

/**
 * @brief Decode a signed integer from BER value bytes
 * 
 * BER signed integers use two's complement.
 * If MSB of first byte is set, the value is negative.
 */
int ber_decode_signed(const uint8_t *data, size_t len, int64_t *result)
{
    if (!data || !result || len == 0) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    if (len > 8) {
        return BER_ERR_OVERFLOW;
    }
    
    /* Sign-extend from the first byte */
    int64_t val = (data[0] & 0x80) ? -1 : 0;
    
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) | data[i];
    }
    
    *result = val;
    return BER_OK;
}

/**
 * @brief Decode a 32-bit big-endian signed integer (fixed width)
 * 
 * SV channel values are always 4 bytes, big-endian, two's complement.
 * This matches ber_encode_int32_fixed() from the encoder.
 */
int ber_decode_int32_be(const uint8_t *data, size_t len, int32_t *result)
{
    if (!data || !result || len < 4) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    *result = (int32_t)(
        ((uint32_t)data[0] << 24) |
        ((uint32_t)data[1] << 16) |
        ((uint32_t)data[2] << 8)  |
        ((uint32_t)data[3])
    );
    
    return BER_OK;
}

/**
 * @brief Decode a 32-bit big-endian unsigned integer (fixed width)
 * 
 * SV quality flags are always 4 bytes, big-endian.
 * This matches ber_encode_uint32_fixed() from the encoder.
 */
int ber_decode_uint32_be(const uint8_t *data, size_t len, uint32_t *result)
{
    if (!data || !result || len < 4) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    *result = ((uint32_t)data[0] << 24) |
              ((uint32_t)data[1] << 16) |
              ((uint32_t)data[2] << 8)  |
              ((uint32_t)data[3]);
    
    return BER_OK;
}

/**
 * @brief Decode a 16-bit big-endian unsigned integer (fixed width)
 * 
 * Used for smpCnt which is always 2 bytes in the encoder.
 */
int ber_decode_uint16_be(const uint8_t *data, size_t len, uint16_t *result)
{
    if (!data || !result || len < 2) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    *result = (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
    
    return BER_OK;
}

/*============================================================================
 * Child Iteration
 *============================================================================*/

/**
 * @brief Iterate through children of a constructed BER element
 * 
 * Usage pattern:
 * ```c
 * BerTLV parent;  // decoded SEQUENCE or constructed tag
 * BerTLV child;
 * size_t offset = 0;
 * 
 * while (ber_decode_next_child(parent.value, parent.length, &offset, &child) == BER_OK) {
 *     // Process child based on child.tag
 *     switch (child.tag) {
 *         case SV_DEC_TAG_SVID:    // decode svID string
 *         case SV_DEC_TAG_SMPCNT:  // decode sample count
 *         // ...
 *     }
 * }
 * ```
 */
int ber_decode_next_child(const uint8_t *parent_value, size_t parent_value_len,
                          size_t *offset, BerTLV *child)
{
    if (!parent_value || !offset || !child) {
        return BER_ERR_BUFFER_SHORT;
    }
    
    /* Check if we've consumed all children */
    if (*offset >= parent_value_len) {
        return BER_ERR_BUFFER_SHORT; /* No more children */
    }
    
    /* Decode next child TLV from current offset */
    int rc = ber_decode_tlv(parent_value + *offset, 
                            parent_value_len - *offset, 
                            child);
    if (rc != BER_OK) {
        return rc;
    }
    
    /* Advance offset past this child */
    *offset += child->total_len;
    
    return BER_OK;
}
