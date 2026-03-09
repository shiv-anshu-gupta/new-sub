/**
 * @file sv_capture.cc
 * @brief Immediate-mode pcap wrapper — open, filter, pcap_next_ex loop, close.
 *
 * Uses pcap_set_immediate_mode(1) so each packet is delivered as soon as
 * it arrives (no kernel batching), then polls with pcap_next_ex() one
 * packet at a time instead of the dispatch/select model.
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
    volatile int     running;   /* cleared by sv_capture_stop() */
};

/* ── Public API ──────────────────────────────────────────────────────────── */

SvCapture *sv_capture_open(const char *interface_name,
                           const char *filter,
                           char *errbuf, size_t errbuf_len)
{
    if (!interface_name || !errbuf) return nullptr;

    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {};

    /* Use pcap_create + pcap_activate so we can enable immediate mode.
       With immediate_mode ON, the AF_PACKET socket delivers every frame
       as soon as it arrives — lowest latency, highest per-packet CPU. */
    pcap_t *p = pcap_create(interface_name, pcap_errbuf);
    if (!p) {
        std::snprintf(errbuf, errbuf_len, "pcap_create: %s", pcap_errbuf);
        return nullptr;
    }
    pcap_set_snaplen(p, SV_CAP_SNAPLEN);
    pcap_set_promisc(p, SV_CAP_PROMISC);
    pcap_set_timeout(p, SV_CAP_TIMEOUT_MS);
    pcap_set_immediate_mode(p, 1);  /* immediate — deliver every frame now */
    int activate_rc = pcap_activate(p);
    if (activate_rc < 0) {
        std::snprintf(errbuf, errbuf_len, "pcap_activate: %s", pcap_geterr(p));
        pcap_close(p);
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
    cap->pcap    = p;
    cap->running = 0;
    return cap;
}

int sv_capture_run(SvCapture *cap, sv_packet_cb cb, void *user_data)
{
    if (!cap || !cb) return -1;

    cap->cb        = cb;
    cap->user_data = user_data;
    cap->running   = 1;

    struct pcap_pkthdr *hdr = nullptr;
    const u_char       *pkt = nullptr;

    while (cap->running) {
        int rc = pcap_next_ex(cap->pcap, &hdr, &pkt);

        if (rc == 1) {
            /* Got a packet — invoke callback */
            uint64_t ts_us = static_cast<uint64_t>(hdr->ts.tv_sec) * 1000000ULL
                           + static_cast<uint64_t>(hdr->ts.tv_usec);
            cap->cb(pkt, hdr->caplen, ts_us, cap->user_data);
        } else if (rc == 0) {
            /* Timeout expired, no packet — just loop back */
            continue;
        } else if (rc == PCAP_ERROR_BREAK) {
            /* pcap_breakloop was called */
            return 0;
        } else {
            /* rc == PCAP_ERROR or other negative value */
            std::fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(cap->pcap));
            return -1;
        }
    }

    return 0;
}

void sv_capture_stop(SvCapture *cap)
{
    if (!cap) return;
    cap->running = 0;
    if (cap->pcap)
        pcap_breakloop(cap->pcap);
}

void sv_capture_close(SvCapture *cap)
{
    if (!cap) return;
    if (cap->pcap) pcap_close(cap->pcap);
    std::free(cap);
}
