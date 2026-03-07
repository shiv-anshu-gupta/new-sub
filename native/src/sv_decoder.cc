/**
 * @file sv_decoder.cc
 * @brief IEC 61850-9-2LE Sampled Values frame decoder
 *
 * Single implementation — combines Ethernet/SV header parsing and
 * BER-based ASDU extraction using asn1_ber_decoder.
 */

#include "sv_decoder.h"
#include "asn1_ber_decoder.h"
#include <cstdio>
#include <cstring>

/* ── Ethernet + SV header parsing ────────────────────────────────────────── */

static int parse_header(const uint8_t *buf, size_t len,
                        SvFrameHeader *hdr, size_t *payload_off)
{
    if (len < 14) return -1;

    size_t pos = 0;
    std::memcpy(hdr->dst_mac, buf + pos, 6); pos += 6;
    std::memcpy(hdr->src_mac, buf + pos, 6); pos += 6;

    uint16_t type_or_vlan = (uint16_t)(buf[pos] << 8 | buf[pos + 1]);

    if (type_or_vlan == SV_VLAN_ETHERTYPE) {
        if (len < 18) return -1;
        hdr->has_vlan = 1;
        pos += 2;
        uint16_t vlan_tag = (uint16_t)(buf[pos] << 8 | buf[pos + 1]);
        hdr->vlan_priority = (vlan_tag >> 13) & 0x07;
        hdr->vlan_id       = vlan_tag & 0x0FFF;
        pos += 2;
        hdr->ether_type = (uint16_t)(buf[pos] << 8 | buf[pos + 1]);
        pos += 2;
    } else {
        hdr->has_vlan     = 0;
        hdr->vlan_id      = 0;
        hdr->vlan_priority = 0;
        hdr->ether_type   = type_or_vlan;
        pos += 2;
    }

    if (hdr->ether_type != SV_ETHERTYPE) return -2;

    /* SV header: AppID(2) + Length(2) + Reserved(4) = 8 bytes */
    if (pos + 8 > len) return -1;

    hdr->app_id    = (uint16_t)(buf[pos] << 8 | buf[pos + 1]); pos += 2;
    hdr->sv_length = (uint16_t)(buf[pos] << 8 | buf[pos + 1]); pos += 2;
    pos += 4; /* skip reserved */

    *payload_off = pos;
    return 0;
}

/* ── Single ASDU decoder ─────────────────────────────────────────────────── */

static void decode_asdu(const uint8_t *data, size_t len, SvAsdu *asdu)
{
    std::memset(asdu, 0, sizeof(*asdu));

    BerTLV child;
    size_t off = 0;

    while (ber_decode_next_child(data, len, &off, &child) == BER_OK) {
        switch (child.tag) {
        case 0x80: { /* svID */
            size_t n = child.length < SV_MAX_SVID_LEN ? child.length : SV_MAX_SVID_LEN;
            std::memcpy(asdu->sv_id, child.value, n);
            asdu->sv_id[n] = '\0';
            break;
        }
        case 0x82: { /* smpCnt */
            if (child.length >= 2)
                ber_decode_uint16_be(child.value, child.length, &asdu->smp_cnt);
            else if (child.length == 1)
                asdu->smp_cnt = child.value[0];
            break;
        }
        case 0x83: { /* confRev */
            if (child.length >= 4) {
                ber_decode_uint32_be(child.value, child.length, &asdu->conf_rev);
            } else {
                uint64_t v = 0;
                ber_decode_unsigned(child.value, child.length, &v);
                asdu->conf_rev = static_cast<uint32_t>(v);
            }
            break;
        }
        case 0x85: /* smpSynch */
            if (child.length >= 1) asdu->smp_synch = child.value[0];
            break;

        case 0x86: /* smpRate (optional) */
            if (child.length >= 2)
                ber_decode_uint16_be(child.value, child.length, &asdu->smp_rate);
            asdu->has_smp_rate = 1;
            break;

        case 0x87: { /* seqData — channel values + quality */
            if (child.length % 8 != 0)
                asdu->errors |= SV_ERR_CHANNEL_DATA_SHORT;

            uint8_t nch = static_cast<uint8_t>(child.length / 8);
            if (nch > SV_MAX_CHANNELS) nch = SV_MAX_CHANNELS;
            asdu->channel_count = nch;

            for (uint8_t ch = 0; ch < nch; ++ch) {
                const uint8_t *p = child.value + ch * 8;
                ber_decode_int32_be(p, 4, &asdu->values[ch]);
                ber_decode_uint32_be(p + 4, 4, &asdu->quality[ch]);
            }
            break;
        }
        default:
            break; /* skip unknown tags */
        }
    }

    if (asdu->sv_id[0] == '\0')
        asdu->errors |= SV_ERR_MISSING_SVID;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

int sv_decode_frame(const uint8_t *buffer, size_t length, SvDecodedFrame *frame)
{
    if (!buffer || !frame) return -1;
    std::memset(frame, 0, sizeof(*frame));
    frame->raw_length = length;

    if (length < 14) {
        frame->errors |= SV_ERR_BUFFER_TOO_SHORT;
        return -1;
    }

    /* 1. Ethernet + SV header */
    size_t payload_off = 0;
    int rc = parse_header(buffer, length, &frame->header, &payload_off);
    if (rc == -2) { frame->errors |= SV_ERR_WRONG_ETHERTYPE; return -1; }
    if (rc == -1) { frame->errors |= SV_ERR_BUFFER_TOO_SHORT; return -1; }

    /* 2. savPdu envelope (tag 0x60) */
    size_t remaining = length - payload_off;
    if (remaining < 2) { frame->errors |= SV_ERR_BER_DECODE_FAIL; return -1; }

    BerTLV sav_pdu;
    if (ber_decode_tlv(buffer + payload_off, remaining, &sav_pdu) != BER_OK ||
        sav_pdu.tag != SV_DEC_TAG_SAVPDU) {
        frame->errors |= SV_ERR_MISSING_SAVPDU;
        return -1;
    }

    /* 3. Iterate savPdu children: noASDU + seqASDU */
    BerTLV child;
    size_t off = 0;
    const uint8_t *seq_data  = nullptr;
    size_t         seq_len   = 0;
    uint8_t found_no   = 0;
    uint8_t found_seq  = 0;

    while (ber_decode_next_child(sav_pdu.value, sav_pdu.length, &off, &child) == BER_OK) {
        if (child.tag == SV_DEC_TAG_NOASDU && child.length >= 1) {
            frame->no_asdu = child.value[0];
            found_no = 1;
        } else if (child.tag == SV_DEC_TAG_SEQASDU) {
            seq_data = child.value;
            seq_len  = child.length;
            found_seq = 1;
        }
    }

    if (!found_no)  frame->errors |= SV_ERR_MISSING_NOASDU;
    if (!found_seq) { frame->errors |= SV_ERR_MISSING_SEQASDU; return -1; }

    /* 4. Decode each ASDU (tag 0x30) */
    BerTLV asdu_tlv;
    size_t seq_off = 0;
    uint8_t idx = 0;

    while (ber_decode_next_child(seq_data, seq_len, &seq_off, &asdu_tlv) == BER_OK) {
        if (asdu_tlv.tag != SV_DEC_TAG_ASDU) continue;
        if (idx >= SV_MAX_ASDUS) break;

        decode_asdu(asdu_tlv.value, asdu_tlv.length, &frame->asdus[idx]);
        ++idx;
    }
    frame->asdu_count = idx;

    if (found_no && frame->asdu_count != frame->no_asdu)
        frame->errors |= SV_ERR_ASDU_COUNT_MISMATCH;

    return 0;
}

const char *sv_error_string(uint32_t bit)
{
    switch (bit) {
    case SV_ERR_BUFFER_TOO_SHORT:    return "Buffer too short";
    case SV_ERR_WRONG_ETHERTYPE:     return "Wrong EtherType (not 0x88BA)";
    case SV_ERR_INVALID_SV_LENGTH:   return "Invalid SV length field";
    case SV_ERR_BER_DECODE_FAIL:     return "BER decode failure";
    case SV_ERR_MISSING_SAVPDU:      return "Missing savPdu (0x60)";
    case SV_ERR_MISSING_NOASDU:      return "Missing noASDU field";
    case SV_ERR_MISSING_SEQASDU:     return "Missing seqASDU field";
    case SV_ERR_MISSING_SVID:        return "ASDU missing svID";
    case SV_ERR_ASDU_COUNT_MISMATCH: return "ASDU count mismatch";
    case SV_ERR_CHANNEL_DATA_SHORT:  return "Channel data length not multiple of 8";
    default:                         return "Unknown error";
    }
}

void sv_format_mac(const uint8_t *mac, char *out, size_t out_len)
{
    if (!mac || !out || out_len < 18) return;
    std::snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
