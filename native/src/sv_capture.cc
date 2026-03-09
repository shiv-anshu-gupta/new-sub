/**
 * @file sv_capture.cc
 * @brief Thin pcap wrapper — open, filter, dispatch, close.
 */

#include "sv_capture.h"
#include <pcap/pcap.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/select.h>
#include <cerrno>
#include <time.h>

/* ── Internal state ──────────────────────────────────────────────────────── */

struct SvCapture {
    pcap_t          *pcap;
    sv_packet_cb     cb;
    void            *user_data;
};

/* ── pcap callback adapter ───────────────────────────────────────────────── */

static void sv_pcap_handler(u_char *user,
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

    /* Use pcap_create + pcap_activate instead of pcap_open_live so we can
       disable immediate mode.  With immediate_mode off, the AF_PACKET
       socket batches frames and only wakes select() at the timeout
       interval (~10 ms) instead of on every single frame (4000 fps). */
    pcap_t *p = pcap_create(interface_name, pcap_errbuf);
    if (!p) {
        std::snprintf(errbuf, errbuf_len, "pcap_create: %s", pcap_errbuf);
        return nullptr;
    }
    pcap_set_snaplen(p, SV_CAP_SNAPLEN);
    pcap_set_promisc(p, SV_CAP_PROMISC);
    pcap_set_timeout(p, SV_CAP_TIMEOUT_MS);
    pcap_set_immediate_mode(p, 0);  /* batch frames — critical for CPU */
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
    cap->pcap = p;
    return cap;
}

int sv_capture_run(SvCapture *cap, sv_packet_cb cb, void *user_data)
{
    if (!cap || !cb) return -1;

    cap->cb        = cb;
    cap->user_data = user_data;

    int fd = pcap_get_selectable_fd(cap->pcap);
    if (fd == PCAP_ERROR) {
        std::fprintf(stderr, "pcap_get_selectable_fd: not supported on this platform\n");
        return -1;
    }

    for (;;) {
        /* Block here until the pcap fd is readable or timeout fires */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv = { 0, SV_CAP_TIMEOUT_MS * 1000 };  /* 10ms */
        int ret = select(fd + 1, &rfds, nullptr, nullptr, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;   /* signal interrupted — retry */
            std::perror("select");
            return -1;
        }

        /* ret == 0 → genuine timeout, no data on socket.  Skip the
           syscall into pcap_dispatch — there is nothing to read.
           pcap_breakloop is checked at the top of the next select(). */
        if (ret == 0) continue;

        int n = pcap_dispatch(cap->pcap, -1,
                              sv_pcap_handler,
                              reinterpret_cast<u_char *>(cap));

        if (n == PCAP_ERROR_BREAK) return 0;
        if (n == PCAP_ERROR) {
            std::fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(cap->pcap));
            return -1;
        }

        /* BPF filter discarded everything (non-SV traffic on a busy link).
           Without this sleep we spin: select(ready) → dispatch(0) → repeat.
           Sleep for the pcap timeout interval to avoid burning CPU. */
        if (n == 0) {
            struct timespec ts = { 0, SV_CAP_TIMEOUT_MS * 1000000L };
            while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
                ;  /* retry on signal interruption */
        }
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
