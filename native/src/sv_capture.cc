/**
 * @file sv_capture.cc
 * @brief Thin pcap wrapper — open, filter, dispatch, close.
 */

#include "sv_capture.h"
#include <pcap/pcap.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>

/* ── Internal state ──────────────────────────────────────────────────────── */

struct SvCapture {
    pcap_t          *pcap;
    sv_packet_cb     cb;
    void            *user_data;
};

/* ── pcap callback adapter ───────────────────────────────────────────────── */

static void pcap_handler(u_char *user,
                         const struct pcap_pkthdr *hdr,
                         const u_char *pkt)
{
    SvCapture *cap = reinterpret_cast<SvCapture *>(user);
    uint64_t ts_us = static_cast<uint64_t>(hdr->ts.tv_sec) * 1000000ULL
                   + static_cast<uint64_t>(hdr->ts.tv_usec);
    cap->cb(pkt, hdr->caplen, ts_us, cap->user_data);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

SvCapture *sv_capture_open(const char *interface_name,
                           const char *filter,
                           char *errbuf, size_t errbuf_len)
{
    if (!interface_name || !errbuf) return nullptr;

    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t *p = pcap_open_live(interface_name,
                               SV_CAP_SNAPLEN,
                               SV_CAP_PROMISC,
                               SV_CAP_TIMEOUT_MS,
                               pcap_errbuf);
    if (!p) {
        std::snprintf(errbuf, errbuf_len, "pcap_open_live: %s", pcap_errbuf);
        return nullptr;
    }

    /* Apply BPF filter */
    const char *bpf = filter ? filter : "ether proto 0x88ba";
    struct bpf_program fp;
    if (pcap_compile(p, &fp, bpf, 1 /* optimise */, PCAP_NETMASK_UNKNOWN) == -1) {
        std::snprintf(errbuf, errbuf_len, "pcap_compile: %s", pcap_geterr(p));
        pcap_close(p);
        return nullptr;
    }
    if (pcap_setfilter(p, &fp) == -1) {
        std::snprintf(errbuf, errbuf_len, "pcap_setfilter: %s", pcap_geterr(p));
        pcap_freecode(&fp);
        pcap_close(p);
        return nullptr;
    }
    pcap_freecode(&fp);

    auto *cap = static_cast<SvCapture *>(std::calloc(1, sizeof(SvCapture)));
    if (!cap) {
        std::snprintf(errbuf, errbuf_len, "out of memory");
        pcap_close(p);
        return nullptr;
    }
    cap->pcap = p;
    return cap;
}

int sv_capture_run(SvCapture *cap, sv_packet_cb cb, void *user_data)
{
    if (!cap || !cb) return -1;

    cap->cb        = cb;
    cap->user_data = user_data;

    /* pcap_dispatch with cnt=0: process all packets available in one
       read timeout period, blocking when idle. No busy loop. */
    for (;;) {
        int n = pcap_dispatch(cap->pcap, 0,
                              pcap_handler,
                              reinterpret_cast<u_char *>(cap));
        if (n == PCAP_ERROR_BREAK) return 0;   /* sv_capture_stop() called */
        if (n == PCAP_ERROR) {
            std::fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(cap->pcap));
            return -1;
        }
        /* n == 0 means timeout with no packets — loop back (blocking) */
    }
}

void sv_capture_stop(SvCapture *cap)
{
    if (cap && cap->pcap)
        pcap_breakloop(cap->pcap);
}

void sv_capture_close(SvCapture *cap)
{
    if (!cap) return;
    if (cap->pcap) pcap_close(cap->pcap);
    std::free(cap);
}
