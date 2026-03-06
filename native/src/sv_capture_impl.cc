/**
 * @file sv_capture_impl.cc
 * @brief SV Packet Capture Implementation using Npcap
 * 
 * This is the RECEIVING counterpart to npcap_transmitter_impl.cc.
 * It uses the same dynamic DLL loading pattern but captures packets
 * using pcap_dispatch (callback-based batch capture) instead of pcap_sendqueue.
 * 
 * Key differences from the transmitter:
 *   - Uses pcap_dispatch() for packet capture (callback-based, CPU-efficient)
 *   - Uses pcap_setfilter() with BPF "ether proto 0x88ba" 
 *   - Uses pcap_breakloop() for clean shutdown
 *   - Spawns a dedicated capture thread
 *   - Each captured frame → sv_highperf_capture_feed() [lock-free SPSC]
 * 
 * Dynamic Loading Functions:
 *   Shared with transmitter:
 *     - pcap_findalldevs / pcap_freealldevs
 *     - pcap_open_live / pcap_close
 *   Capture-specific:
 *     - pcap_dispatch          (callback-based batch capture)
 *     - pcap_compile           (compile BPF filter)
 *     - pcap_setfilter         (apply BPF filter)
 *     - pcap_breakloop         (interrupt pcap_dispatch loop)
 *     - pcap_datalink          (check link layer type)
 *     - pcap_stats             (kernel drop stats)
 */

#include "../include/sv_capture.h"
#include "../include/sv_decoder.h"  /* for SV EtherType constants */
#include "../include/sv_highperf.h" /* for high-perf pipeline */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <thread>
#include <chrono>

/*============================================================================
 * Platform-Specific Includes
 *============================================================================*/

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <mmsystem.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")

/*============================================================================
 * Npcap Types (mirrored from npcap_transmitter_impl.cc)
 *============================================================================*/

typedef void* pcap_t;
typedef struct pcap_if pcap_if_t;

struct pcap_if {
    struct pcap_if* next;
    char* name;
    char* description;
    void* addresses;
    unsigned int flags;
};

struct pcap_pkthdr {
    struct { long tv_sec; long tv_usec; } ts;
    unsigned int caplen;
    unsigned int len;
};

struct bpf_insn {
    unsigned short code;
    unsigned char jt;
    unsigned char jf;
    unsigned int k;
};

struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn* bf_insns;
};

struct pcap_stat {
    unsigned int ps_recv;
    unsigned int ps_drop;
    unsigned int ps_ifdrop;
};

/*============================================================================
 * Function Pointer Types
 *============================================================================*/

/* Shared with transmitter */
typedef int     (*pcap_findalldevs_t)(pcap_if_t**, char*);
typedef void    (*pcap_freealldevs_t)(pcap_if_t*);
typedef pcap_t* (*pcap_open_live_t)(const char*, int, int, int, char*);
typedef void    (*pcap_close_t)(pcap_t*);

/* Capture-specific */
typedef int     (*pcap_next_ex_t)(pcap_t*, struct pcap_pkthdr**, const unsigned char**);
typedef const unsigned char* (*pcap_next_t)(pcap_t*, struct pcap_pkthdr*);
typedef int     (*pcap_compile_t)(pcap_t*, struct bpf_program*, const char*, int, unsigned int);
typedef int     (*pcap_setfilter_t)(pcap_t*, struct bpf_program*);
typedef void    (*pcap_freecode_t)(struct bpf_program*);
typedef void    (*pcap_breakloop_t)(pcap_t*);
typedef int     (*pcap_datalink_t)(pcap_t*);
typedef int     (*pcap_stats_t)(pcap_t*, struct pcap_stat*);

/* pcap_dispatch — callback-based batch capture (lower CPU than pcap_next_ex polling) */
typedef void    (*pcap_handler_t)(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);
typedef int     (*pcap_dispatch_t)(pcap_t*, int, pcap_handler_t, unsigned char*);

/* pcap_create/activate pattern (replaces pcap_open_live for timestamp control) */
typedef pcap_t* (*pcap_create_t)(const char*, char*);
typedef int     (*pcap_activate_t)(pcap_t*);
typedef int     (*pcap_set_snaplen_t)(pcap_t*, int);
typedef int     (*pcap_set_promisc_t)(pcap_t*, int);
typedef int     (*pcap_set_timeout_t)(pcap_t*, int);
typedef int     (*pcap_set_buffer_size_t)(pcap_t*, int);
typedef int     (*pcap_set_immediate_mode_t)(pcap_t*, int);

/* Timestamp type/precision API (Npcap high-precision timestamps) */
typedef int     (*pcap_list_tstamp_types_t)(pcap_t*, int**);
typedef void    (*pcap_free_tstamp_types_t)(int*);
typedef int     (*pcap_set_tstamp_type_t)(pcap_t*, int);
typedef int     (*pcap_set_tstamp_precision_t)(pcap_t*, int);
typedef int     (*pcap_get_tstamp_precision_t)(pcap_t*);
typedef const char* (*pcap_tstamp_type_val_to_name_t)(int);

/*============================================================================
 * Module State
 *============================================================================*/

static HMODULE              g_dll = nullptr;

/* Shared functions */
static pcap_findalldevs_t   g_findalldevs = nullptr;
static pcap_freealldevs_t   g_freealldevs = nullptr;
static pcap_open_live_t     g_open_live = nullptr;
static pcap_close_t         g_close = nullptr;

/* Capture functions */
static pcap_next_ex_t       g_next_ex = nullptr;
static pcap_next_t          g_next = nullptr;
static pcap_compile_t       g_compile = nullptr;
static pcap_setfilter_t     g_setfilter = nullptr;
static pcap_freecode_t      g_freecode = nullptr;
static pcap_breakloop_t     g_breakloop = nullptr;
static pcap_datalink_t      g_datalink = nullptr;
static pcap_stats_t         g_pcap_stats = nullptr;
static pcap_dispatch_t      g_dispatch = nullptr;

/* pcap_create/activate functions */
static pcap_create_t        g_pcap_create = nullptr;
static pcap_activate_t      g_pcap_activate = nullptr;
static pcap_set_snaplen_t   g_pcap_set_snaplen = nullptr;
static pcap_set_promisc_t   g_pcap_set_promisc = nullptr;
static pcap_set_timeout_t   g_pcap_set_timeout = nullptr;
static pcap_set_buffer_size_t g_pcap_set_buffer_size = nullptr;
static pcap_set_immediate_mode_t g_pcap_set_immediate_mode = nullptr;

/* Timestamp API functions */
static pcap_list_tstamp_types_t     g_pcap_list_tstamp_types = nullptr;
static pcap_free_tstamp_types_t     g_pcap_free_tstamp_types = nullptr;
static pcap_set_tstamp_type_t       g_pcap_set_tstamp_type = nullptr;
static pcap_set_tstamp_precision_t  g_pcap_set_tstamp_precision = nullptr;
static pcap_get_tstamp_precision_t  g_pcap_get_tstamp_precision = nullptr;
static pcap_tstamp_type_val_to_name_t g_pcap_tstamp_type_val_to_name = nullptr;

static pcap_t*              g_handle = nullptr;

#else
/* Linux/macOS - link directly against libpcap */
#include <pcap/pcap.h>
static pcap_t*              g_handle = nullptr;
#endif

/*============================================================================
 * Timestamp Type Constants (cross-platform)
 * On Windows these mirror Npcap's pcap.h values; on Linux pcap/pcap.h provides
 * PCAP_TSTAMP_* but we use our own SV_PCAP_TSTAMP_* names throughout.
 *============================================================================*/

#define SV_PCAP_TSTAMP_HOST              0
#define SV_PCAP_TSTAMP_HOST_LOWPREC      1
#define SV_PCAP_TSTAMP_HOST_HIPREC       2
#define SV_PCAP_TSTAMP_ADAPTER           3
#define SV_PCAP_TSTAMP_ADAPTER_UNSYNCED  4
#define SV_PCAP_TSTAMP_HOST_HIPREC_UNSYNCED 5

#define SV_PCAP_TSTAMP_PRECISION_MICRO   0
#define SV_PCAP_TSTAMP_PRECISION_NANO    1

/*============================================================================
 * Capture State
 *============================================================================*/

static char                 g_error[512] = {0};
static std::atomic<bool>    g_capturing{false};
static std::thread          g_capture_thread;

/* Statistics */
static std::atomic<uint64_t> g_stat_received{0};
static std::atomic<uint64_t> g_stat_sv{0};
static std::atomic<uint64_t> g_stat_dropped{0};
static std::atomic<uint64_t> g_stat_bytes{0};
static uint64_t              g_capture_start_ms = 0;

/* Timestamp precision state — tracks what was actually configured */
static int  g_tstamp_type = 0;        /**< Active timestamp type (SV_PCAP_TSTAMP_*) */
static int  g_tstamp_precision = 0;    /**< Active precision (MICRO=0, NANO=1) */
static bool g_tstamp_nano_active = false; /**< True if nanosecond precision was successfully set */
static char g_tstamp_type_name[64] = "host"; /**< Human-readable name of active timestamp type */

/* JSON output buffer */
#define CAP_JSON_BUF_SIZE   8192
static char g_json_buf[CAP_JSON_BUF_SIZE];

/*============================================================================
 * Utility
 *============================================================================*/

static uint64_t get_time_ms() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

/*============================================================================
 * DLL Loading (Windows)
 *============================================================================*/

extern "C" {

int sv_capture_load_dll(void) {
#ifdef _WIN32
    if (g_dll) return 1; /* Already loaded */
    
    /* Try Npcap path first (System32\Npcap\), then fallback */
    char npcap_dir[MAX_PATH];
    char path[MAX_PATH];
    
    /* Method 1: SetDllDirectory (recommended by Npcap docs) */
    if (GetEnvironmentVariableA("SystemRoot", npcap_dir, MAX_PATH)) {
        strcat(npcap_dir, "\\System32\\Npcap");
        SetDllDirectoryA(npcap_dir);
        
        snprintf(path, MAX_PATH, "%s\\wpcap.dll", npcap_dir);
        printf("[capture] Trying DLL path: %s\n", path);
        g_dll = LoadLibraryA(path);
    }
    
    /* Method 2: Direct system path */
    if (!g_dll) {
        printf("[capture] Trying fallback: wpcap.dll\n");
        g_dll = LoadLibraryA("wpcap.dll");
    }
    
    /* Method 3: Npcap SDK registry path */
    if (!g_dll) {
        HKEY key;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Npcap", 0, KEY_READ, &key) == ERROR_SUCCESS ||
            RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Npcap", 0, KEY_READ, &key) == ERROR_SUCCESS) {
            DWORD size = MAX_PATH;
            char install_path[MAX_PATH];
            if (RegQueryValueExA(key, "InstallDir", NULL, NULL, (LPBYTE)install_path, &size) == ERROR_SUCCESS) {
                snprintf(path, MAX_PATH, "%s\\wpcap.dll", install_path);
                printf("[capture] Trying registry path: %s\n", path);
                g_dll = LoadLibraryA(path);
            }
            RegCloseKey(key);
        }
    }
    
    if (!g_dll) {
        snprintf(g_error, sizeof(g_error),
            "Npcap not found. Install from https://npcap.com/");
        printf("[capture] ERROR: %s\n", g_error);
        return 0;
    }
    
    /* Load shared functions */
    g_findalldevs = (pcap_findalldevs_t)GetProcAddress(g_dll, "pcap_findalldevs");
    g_freealldevs = (pcap_freealldevs_t)GetProcAddress(g_dll, "pcap_freealldevs");
    g_open_live   = (pcap_open_live_t)GetProcAddress(g_dll, "pcap_open_live");
    g_close       = (pcap_close_t)GetProcAddress(g_dll, "pcap_close");
    
    /* Load capture-specific functions */
    g_next_ex     = (pcap_next_ex_t)GetProcAddress(g_dll, "pcap_next_ex");
    g_next        = (pcap_next_t)GetProcAddress(g_dll, "pcap_next");
    g_compile     = (pcap_compile_t)GetProcAddress(g_dll, "pcap_compile");
    g_setfilter   = (pcap_setfilter_t)GetProcAddress(g_dll, "pcap_setfilter");
    g_freecode    = (pcap_freecode_t)GetProcAddress(g_dll, "pcap_freecode");
    g_breakloop   = (pcap_breakloop_t)GetProcAddress(g_dll, "pcap_breakloop");
    g_datalink    = (pcap_datalink_t)GetProcAddress(g_dll, "pcap_datalink");
    g_pcap_stats  = (pcap_stats_t)GetProcAddress(g_dll, "pcap_stats");
    g_dispatch    = (pcap_dispatch_t)GetProcAddress(g_dll, "pcap_dispatch");
    
    /* Load pcap_create/activate pattern functions */
    g_pcap_create      = (pcap_create_t)GetProcAddress(g_dll, "pcap_create");
    g_pcap_activate    = (pcap_activate_t)GetProcAddress(g_dll, "pcap_activate");
    g_pcap_set_snaplen = (pcap_set_snaplen_t)GetProcAddress(g_dll, "pcap_set_snaplen");
    g_pcap_set_promisc = (pcap_set_promisc_t)GetProcAddress(g_dll, "pcap_set_promisc");
    g_pcap_set_timeout = (pcap_set_timeout_t)GetProcAddress(g_dll, "pcap_set_timeout");
    g_pcap_set_buffer_size = (pcap_set_buffer_size_t)GetProcAddress(g_dll, "pcap_set_buffer_size");
    g_pcap_set_immediate_mode = (pcap_set_immediate_mode_t)GetProcAddress(g_dll, "pcap_set_immediate_mode");
    
    /* Load timestamp API functions */
    g_pcap_list_tstamp_types     = (pcap_list_tstamp_types_t)GetProcAddress(g_dll, "pcap_list_tstamp_types");
    g_pcap_free_tstamp_types     = (pcap_free_tstamp_types_t)GetProcAddress(g_dll, "pcap_free_tstamp_types");
    g_pcap_set_tstamp_type       = (pcap_set_tstamp_type_t)GetProcAddress(g_dll, "pcap_set_tstamp_type");
    g_pcap_set_tstamp_precision  = (pcap_set_tstamp_precision_t)GetProcAddress(g_dll, "pcap_set_tstamp_precision");
    g_pcap_get_tstamp_precision  = (pcap_get_tstamp_precision_t)GetProcAddress(g_dll, "pcap_get_tstamp_precision");
    g_pcap_tstamp_type_val_to_name = (pcap_tstamp_type_val_to_name_t)GetProcAddress(g_dll, "pcap_tstamp_type_val_to_name");
    
    /* Validate required functions */
    if (!g_findalldevs || !g_freealldevs || !g_open_live || !g_close || !g_next) {
        FreeLibrary(g_dll);
        g_dll = nullptr;
        snprintf(g_error, sizeof(g_error), "Failed to load required Npcap functions");
        printf("[capture] ERROR: %s\n", g_error);
        return 0;
    }
    
    printf("[capture] Npcap DLL loaded (capture mode)\n");
    printf("[capture]   pcap_next: %s\n", g_next ? "OK" : "MISSING");
    printf("[capture]   pcap_next_ex: %s\n", g_next_ex ? "OK" : "MISSING");
    printf("[capture]   pcap_compile: %s\n", g_compile ? "OK" : "MISSING");
    printf("[capture]   pcap_setfilter: %s\n", g_setfilter ? "OK" : "MISSING");
    printf("[capture]   pcap_breakloop: %s\n", g_breakloop ? "OK" : "MISSING");
    printf("[capture]   pcap_create: %s\n", g_pcap_create ? "OK" : "MISSING");
    printf("[capture]   pcap_activate: %s\n", g_pcap_activate ? "OK" : "MISSING");
    printf("[capture]   pcap_list_tstamp_types: %s\n", g_pcap_list_tstamp_types ? "OK" : "MISSING");
    printf("[capture]   pcap_set_tstamp_type: %s\n", g_pcap_set_tstamp_type ? "OK" : "MISSING");
    printf("[capture]   pcap_set_tstamp_precision: %s\n", g_pcap_set_tstamp_precision ? "OK" : "MISSING");
    printf("[capture]   pcap_set_immediate_mode: %s\n", g_pcap_set_immediate_mode ? "OK" : "MISSING");
    printf("[capture]   pcap_dispatch: %s\n", g_dispatch ? "OK" : "MISSING");
    
    return 1;
#else
    return 1; /* libpcap linked directly on Unix */
#endif
}

int sv_capture_dll_loaded(void) {
#ifdef _WIN32
    return g_dll ? 1 : 0;
#else
    return 1;
#endif
}

/*============================================================================
 * Interface Enumeration
 *============================================================================*/

int sv_capture_list_interfaces(SvCaptureInterface *interfaces, int max_count) {
    printf("[capture] Listing network interfaces...\n");
    
    if (!interfaces || max_count <= 0) return -1;
    
#ifdef _WIN32
    if (!sv_capture_load_dll()) return -1;
    
    pcap_if_t* alldevs = nullptr;
    char errbuf[256] = {0};
    
    if (g_findalldevs(&alldevs, errbuf) == -1) {
        snprintf(g_error, sizeof(g_error), "pcap_findalldevs failed: %s", errbuf);
        printf("[capture] ERROR: %s\n", g_error);
        return -1;
    }
    
    if (!alldevs) {
        printf("[capture] WARNING: No interfaces found\n");
        return 0;
    }
    
    int count = 0;
    for (pcap_if_t* d = alldevs; d && count < max_count; d = d->next) {
        SvCaptureInterface* iface = &interfaces[count];
        memset(iface, 0, sizeof(SvCaptureInterface));
        
        if (d->name) strncpy(iface->name, d->name, sizeof(iface->name) - 1);
        if (d->description) strncpy(iface->description, d->description, sizeof(iface->description) - 1);
        
        /* Resolve MAC address via Windows GetAdaptersInfo */
        PIP_ADAPTER_INFO adapterInfo = nullptr;
        ULONG bufLen = 0;
        
        if (GetAdaptersInfo(adapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
            adapterInfo = (PIP_ADAPTER_INFO)malloc(bufLen);
            if (adapterInfo && GetAdaptersInfo(adapterInfo, &bufLen) == NO_ERROR) {
                for (PIP_ADAPTER_INFO ai = adapterInfo; ai; ai = ai->Next) {
                    if (d->name && strstr(d->name, ai->AdapterName)) {
                        memcpy(iface->mac, ai->Address, 6);
                        iface->has_mac = 1;
                        break;
                    }
                }
            }
            if (adapterInfo) free(adapterInfo);
        }
        
        printf("[capture] Interface %d: %s %s (MAC: %s)\n", count,
               iface->description[0] ? iface->description : iface->name,
               iface->name,
               iface->has_mac ? "found" : "none");
        count++;
    }
    
    g_freealldevs(alldevs);
    printf("[capture] Total: %d interfaces found\n", count);
    return count;
    
#else
    /* Linux/macOS: direct pcap calls */
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        snprintf(g_error, sizeof(g_error), "%s", errbuf);
        return -1;
    }
    
    int count = 0;
    for (pcap_if_t* d = alldevs; d && count < max_count; d = d->next) {
        SvCaptureInterface* iface = &interfaces[count++];
        memset(iface, 0, sizeof(SvCaptureInterface));
        if (d->name) strncpy(iface->name, d->name, sizeof(iface->name) - 1);
        if (d->description) strncpy(iface->description, d->description, sizeof(iface->description) - 1);
    }
    pcap_freealldevs(alldevs);
    return count;
#endif
}

/*============================================================================
 * Interface Open / Close
 *============================================================================*/

int sv_capture_open(const char *device_name) {
    if (!device_name) {
        snprintf(g_error, sizeof(g_error), "Device name is NULL");
        return -1;
    }
    
    printf("[capture] Opening: %s\n", device_name);
    
#ifdef _WIN32
    if (!sv_capture_load_dll()) return -1;
    
    /* Close existing handle if any */
    if (g_handle) { g_close(g_handle); g_handle = nullptr; }
    
    char errbuf[256];
    
    /* ════════════════════════════════════════════════════════════════════
     * HIGH-PRECISION TIMESTAMP: pcap_create() + configure + pcap_activate()
     *
     * pcap_open_live() doesn't allow setting timestamp type/precision.
     * We use pcap_create() → set_snaplen → set_promisc → set_timeout →
     * query/set timestamp type → set nanosecond precision → pcap_activate().
     *
     * Timestamp type priority:
     *   1. PCAP_TSTAMP_ADAPTER (3)          — NIC hardware clock (nanosecond)
     *   2. PCAP_TSTAMP_HOST_HIPREC (2)      — OS high-precision software clock
     *   3. PCAP_TSTAMP_HOST (0)             — Default (millisecond on Windows)
     * ════════════════════════════════════════════════════════════════════ */
    
    bool use_create_activate = g_pcap_create && g_pcap_activate 
                               && g_pcap_set_snaplen && g_pcap_set_promisc 
                               && g_pcap_set_timeout;
    
    if (use_create_activate) {
        /* Step 1: Create handle (not yet activated) */
        g_handle = g_pcap_create(device_name, errbuf);
        if (!g_handle) {
            snprintf(g_error, sizeof(g_error), "pcap_create: %s", errbuf);
            printf("[capture] ERROR: %s\n", g_error);
            return -1;
        }
        
        /* Step 2: Configure basic capture parameters */
        g_pcap_set_snaplen(g_handle, SV_CAP_SNAPLEN);
        g_pcap_set_promisc(g_handle, SV_CAP_PROMISC);
        g_pcap_set_timeout(g_handle, SV_CAP_TIMEOUT_MS);
        
        /* Set kernel capture buffer to 10 MB (default is ~2 MB on most systems) */
        if (g_pcap_set_buffer_size) {
            int rc = g_pcap_set_buffer_size(g_handle, SV_CAP_BUFFER_SIZE);
            if (rc == 0) {
                printf("[capture] Kernel buffer size set to %d MB\n", SV_CAP_BUFFER_SIZE / (1024*1024));
            } else {
                printf("[capture] WARNING: pcap_set_buffer_size failed (rc=%d)\n", rc);
            }
        }
        
        /* Step 2b: Immediate mode DISABLED — we use pcap_dispatch() with
         * buffered delivery to avoid 100% CPU busy-polling.
         * The OS/driver batches packets and delivers them per timeout interval,
         * and pcap_dispatch processes the entire batch via callback. */
        printf("[capture] Immediate mode disabled (using pcap_dispatch buffered delivery)\n");
        
        /* Step 3: Query and set best available timestamp type */
        g_tstamp_type = SV_PCAP_TSTAMP_HOST;  /* Default fallback */
        strncpy(g_tstamp_type_name, "host", sizeof(g_tstamp_type_name));
        
        if (g_pcap_list_tstamp_types && g_pcap_set_tstamp_type) {
            int *tstamp_types = nullptr;
            int num_types = g_pcap_list_tstamp_types(g_handle, &tstamp_types);
            
            if (num_types > 0 && tstamp_types) {
                printf("[capture] Adapter supports %d timestamp type(s):\n", num_types);
                
                bool has_adapter = false;
                bool has_hiprec = false;
                
                for (int i = 0; i < num_types; i++) {
                    const char *name = "unknown";
                    if (g_pcap_tstamp_type_val_to_name) {
                        name = g_pcap_tstamp_type_val_to_name(tstamp_types[i]);
                        if (!name) name = "unknown";
                    }
                    printf("[capture]   [%d] type=%d (%s)\n", i, tstamp_types[i], name);
                    
                    if (tstamp_types[i] == SV_PCAP_TSTAMP_ADAPTER) has_adapter = true;
                    if (tstamp_types[i] == SV_PCAP_TSTAMP_HOST_HIPREC) has_hiprec = true;
                }
                
                /* Priority selection: ADAPTER > HOST_HIPREC > HOST */
                if (has_adapter) {
                    int rc = g_pcap_set_tstamp_type(g_handle, SV_PCAP_TSTAMP_ADAPTER);
                    if (rc == 0) {
                        g_tstamp_type = SV_PCAP_TSTAMP_ADAPTER;
                        strncpy(g_tstamp_type_name, "adapter", sizeof(g_tstamp_type_name));
                        printf("[capture] ✓ Timestamp type set: PCAP_TSTAMP_ADAPTER (hardware NIC clock)\n");
                    } else {
                        printf("[capture] WARNING: pcap_set_tstamp_type(ADAPTER) failed (rc=%d), trying HIPREC\n", rc);
                        has_adapter = false; /* Fall through to HIPREC */
                    }
                }
                
                if (!has_adapter && has_hiprec) {
                    int rc = g_pcap_set_tstamp_type(g_handle, SV_PCAP_TSTAMP_HOST_HIPREC);
                    if (rc == 0) {
                        g_tstamp_type = SV_PCAP_TSTAMP_HOST_HIPREC;
                        strncpy(g_tstamp_type_name, "host_hiprec", sizeof(g_tstamp_type_name));
                        printf("[capture] ✓ Timestamp type set: PCAP_TSTAMP_HOST_HIPREC (OS high-precision clock)\n");
                    } else {
                        printf("[capture] WARNING: pcap_set_tstamp_type(HOST_HIPREC) failed (rc=%d)\n", rc);
                    }
                }
                
                if (g_pcap_free_tstamp_types && tstamp_types) {
                    g_pcap_free_tstamp_types(tstamp_types);
                }
            } else {
                printf("[capture] No selectable timestamp types listed by adapter\n");
            }
        }
        
        /* Force-set HOST_HIPREC if not already set.
         * Many adapters (Intel, Realtek) don't advertise HOST_HIPREC
         * in pcap_list_tstamp_types(), but Npcap still supports it
         * system-wide via QPC. Always try to set it. */
        if (g_tstamp_type == SV_PCAP_TSTAMP_HOST && g_pcap_set_tstamp_type) {
            int rc = g_pcap_set_tstamp_type(g_handle, SV_PCAP_TSTAMP_HOST_HIPREC);
            if (rc == 0) {
                g_tstamp_type = SV_PCAP_TSTAMP_HOST_HIPREC;
                strncpy(g_tstamp_type_name, "host_hiprec", sizeof(g_tstamp_type_name));
                printf("[capture] \xe2\x9c\x93 Force-set HOST_HIPREC (adapter didn't advertise, but Npcap supports it)\n");
            } else {
                printf("[capture] HOST_HIPREC force-set failed (rc=%d), using HOST (~1ms resolution)\n", rc);
                printf("[capture] WARNING: Timestamps may have duplicates at high sample rates!\n");
            }
        }
        
        if (g_tstamp_type == SV_PCAP_TSTAMP_HOST) {
            printf("[capture] Using default PCAP_TSTAMP_HOST (standard OS clock, ~1ms resolution)\n");
        }
        
        /* Step 4: Request nanosecond precision */
        g_tstamp_precision = SV_PCAP_TSTAMP_PRECISION_MICRO;
        g_tstamp_nano_active = false;
        
        if (g_pcap_set_tstamp_precision) {
            int rc = g_pcap_set_tstamp_precision(g_handle, SV_PCAP_TSTAMP_PRECISION_NANO);
            if (rc == 0) {
                g_tstamp_precision = SV_PCAP_TSTAMP_PRECISION_NANO;
                g_tstamp_nano_active = true;
                printf("[capture] ✓ Timestamp precision set: NANOSECOND\n");
            } else {
                printf("[capture] Nanosecond precision not available, using MICROSECOND\n");
            }
        }
        
        /* Step 5: Activate the handle */
        int activate_rc = g_pcap_activate(g_handle);
        if (activate_rc < 0) {
            /* Negative = error */
            snprintf(g_error, sizeof(g_error), "pcap_activate failed (rc=%d)", activate_rc);
            printf("[capture] ERROR: %s\n", g_error);
            g_close(g_handle);
            g_handle = nullptr;
            return -1;
        }
        if (activate_rc > 0) {
            /* Positive = warning (e.g., promiscuous mode not supported) */
            printf("[capture] WARNING: pcap_activate returned warning %d (continuing)\n", activate_rc);
        }
        
        /* Verify actual precision after activation */
        if (g_pcap_get_tstamp_precision) {
            int actual_prec = g_pcap_get_tstamp_precision(g_handle);
            g_tstamp_nano_active = (actual_prec == SV_PCAP_TSTAMP_PRECISION_NANO);
            printf("[capture] Actual timestamp precision after activate: %s\n",
                   g_tstamp_nano_active ? "NANOSECOND" : "MICROSECOND");
        }
        
        printf("[capture] Interface opened via pcap_create+activate (tstamp=%s, precision=%s)\n",
               g_tstamp_type_name,
               g_tstamp_nano_active ? "nano" : "micro");
    } else {
        /* Fallback: pcap_create/activate not available, use legacy pcap_open_live */
        printf("[capture] pcap_create/activate not available, falling back to pcap_open_live\n");
        g_handle = g_open_live(device_name, SV_CAP_SNAPLEN, SV_CAP_PROMISC, SV_CAP_TIMEOUT_MS, errbuf);
        if (!g_handle) {
            snprintf(g_error, sizeof(g_error), "pcap_open_live: %s", errbuf);
            printf("[capture] ERROR: %s\n", g_error);
            return -1;
        }
        g_tstamp_type = SV_PCAP_TSTAMP_HOST;
        strncpy(g_tstamp_type_name, "host", sizeof(g_tstamp_type_name));
        g_tstamp_precision = SV_PCAP_TSTAMP_PRECISION_MICRO;
        g_tstamp_nano_active = false;
    }
    
    /* Apply BPF filter for SV EtherType 0x88BA */
    if (g_compile && g_setfilter) {
        struct bpf_program fp;
        memset(&fp, 0, sizeof(fp));
        
        /* Filter: capture only SV frames (EtherType 0x88BA) */
        const char* filter_expr = "ether proto 0x88ba";
        
        if (g_compile(g_handle, &fp, filter_expr, 1, 0) == 0) {
            if (g_setfilter(g_handle, &fp) == 0) {
                printf("[capture] BPF filter applied: '%s'\n", filter_expr);
            } else {
                printf("[capture] WARNING: pcap_setfilter failed, capturing all traffic\n");
            }
            if (g_freecode) g_freecode(&fp);
        } else {
            printf("[capture] WARNING: pcap_compile failed for '%s', capturing all traffic\n", filter_expr);
        }
    } else {
        printf("[capture] WARNING: BPF filter functions not available, will filter manually\n");
    }
    
    /* Verify link layer type is Ethernet */
    if (g_datalink) {
        int dlt = g_datalink(g_handle);
        if (dlt != 1) { /* DLT_EN10MB = 1 */
            printf("[capture] WARNING: Link type is %d (expected 1=Ethernet)\n", dlt);
        } else {
            printf("[capture] Link type: Ethernet (DLT_EN10MB)\n");
        }
    }
    
#else
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* ════════════════════════════════════════════════════════════════════
     * HIGH-PRECISION TIMESTAMP: pcap_create() + configure + pcap_activate()
     * Same workflow as Windows path — immediate mode + HOST_HIPREC
     * ════════════════════════════════════════════════════════════════════ */
    g_handle = pcap_create(device_name, errbuf);
    if (!g_handle) {
        snprintf(g_error, sizeof(g_error), "pcap_create: %s", errbuf);
        return -1;
    }
    
    pcap_set_snaplen(g_handle, SV_CAP_SNAPLEN);
    pcap_set_promisc(g_handle, SV_CAP_PROMISC);
    pcap_set_timeout(g_handle, SV_CAP_TIMEOUT_MS);  /* 2ms timeout — pcap_dispatch batched delivery */
    pcap_set_buffer_size(g_handle, SV_CAP_BUFFER_SIZE); /* 10 MB kernel buffer */
    /* Immediate mode DISABLED — pcap_dispatch handles batched packet
     * delivery efficiently without busy-spinning the CPU. */
    /* pcap_set_immediate_mode(g_handle, 0); — default is already off */
    
    /* Try best available timestamp type: ADAPTER > HOST_HIPREC > HOST */
    int *tstamp_types = nullptr;
    int num_types = pcap_list_tstamp_types(g_handle, &tstamp_types);
    if (num_types > 0 && tstamp_types) {
        bool has_adapter = false, has_hiprec = false;
        for (int i = 0; i < num_types; i++) {
            if (tstamp_types[i] == PCAP_TSTAMP_ADAPTER) has_adapter = true;
            if (tstamp_types[i] == PCAP_TSTAMP_HOST_HIPREC) has_hiprec = true;
        }
        if (has_adapter) {
            pcap_set_tstamp_type(g_handle, PCAP_TSTAMP_ADAPTER);
            printf("[capture] Timestamp: ADAPTER (hardware)\n");
        } else if (has_hiprec) {
            pcap_set_tstamp_type(g_handle, PCAP_TSTAMP_HOST_HIPREC);
            printf("[capture] Timestamp: HOST_HIPREC\n");
        }
        pcap_free_tstamp_types(tstamp_types);
    }
    
    /* Request nanosecond precision */
    pcap_set_tstamp_precision(g_handle, PCAP_TSTAMP_PRECISION_NANO);
    
    int activate_rc = pcap_activate(g_handle);
    if (activate_rc < 0) {
        const char* pcap_err = pcap_geterr(g_handle);
        if (activate_rc == -8) {
            /* PCAP_ERROR_PERM_DENIED */
            snprintf(g_error, sizeof(g_error),
                "Permission denied. Raw packet capture requires root or CAP_NET_RAW. "
                "Run with: sudo ./sv-subscriber  OR  "
                "sudo setcap cap_net_raw,cap_net_admin=eip <binary>");
        } else if (activate_rc == -9) {
            /* PCAP_ERROR_IFACE_NOT_UP */
            snprintf(g_error, sizeof(g_error),
                "Interface is not up. Run: sudo ip link set <iface> up");
        } else {
            snprintf(g_error, sizeof(g_error),
                "pcap_activate failed (rc=%d): %s", activate_rc,
                pcap_err ? pcap_err : "unknown error");
        }
        printf("[capture] ERROR: %s\n", g_error);
        pcap_close(g_handle);
        g_handle = nullptr;
        return -1;
    }
    if (activate_rc > 0) {
        printf("[capture] WARNING: pcap_activate warning %d\n", activate_rc);
    }
    
    /* Apply BPF filter */
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "ether proto 0x88ba", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(g_handle, &fp);
        pcap_freecode(&fp);
    }
#endif
    
    printf("[capture] Interface opened successfully\n");
    return 0;
}

void sv_capture_close(void) {
    /* Stop capture first if running */
    if (g_capturing.load()) {
        sv_capture_stop();
    }
    
#ifdef _WIN32
    if (g_handle && g_close) { g_close(g_handle); g_handle = nullptr; }
#else
    if (g_handle) { pcap_close(g_handle); g_handle = nullptr; }
#endif
    
    printf("[capture] Interface closed\n");
}

int sv_capture_is_open(void) {
    return g_handle ? 1 : 0;
}

/*============================================================================
 * Capture Thread
 *============================================================================*/

/*============================================================================
 * pcap_dispatch Callback — processes each packet in the batch
 *
 * Called by pcap_dispatch() for each packet in the kernel buffer.
 * This replaces the old pcap_next_ex() busy-polling loop to avoid
 * 100% CPU. The OS batches packets and delivers them per timeout.
 *============================================================================*/

#ifdef _WIN32
static void capture_dispatch_cb(unsigned char *user_data,
                                const struct pcap_pkthdr *header,
                                const unsigned char *pkt_data) {
    (void)user_data;
    g_stat_received.fetch_add(1, std::memory_order_relaxed);
    g_stat_bytes.fetch_add(header->caplen, std::memory_order_relaxed);
    
    if (header->caplen >= 14 && pkt_data) {
        uint64_t ts_us;
        if (g_tstamp_nano_active) {
            ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL
                  + (uint64_t)header->ts.tv_usec / 1000ULL;
        } else {
            ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL
                  + (uint64_t)header->ts.tv_usec;
        }
        int rc = sv_highperf_capture_feed(pkt_data, header->caplen, ts_us);
        if (rc == 0) {
            g_stat_sv.fetch_add(1, std::memory_order_relaxed);
        }
    }
}
#else
static void capture_dispatch_cb(u_char *user_data,
                                const struct pcap_pkthdr *header,
                                const u_char *pkt_data) {
    (void)user_data;
    g_stat_received.fetch_add(1, std::memory_order_relaxed);
    g_stat_bytes.fetch_add(header->caplen, std::memory_order_relaxed);
    
    if (header->caplen >= 14 && pkt_data) {
        uint64_t ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL
                       + (uint64_t)header->ts.tv_usec;
        int rc = sv_highperf_capture_feed(pkt_data, header->caplen, ts_us);
        if (rc == 0) g_stat_sv.fetch_add(1, std::memory_order_relaxed);
    }
}
#endif

/**
 * @brief Capture thread function — EFFICIENT pcap_dispatch PATH
 * 
 * Uses pcap_dispatch() with callback-based batch processing.
 * The OS kernel buffers packets and delivers them every ~10ms (SV_CAP_TIMEOUT_MS).
 * pcap_dispatch processes ALL buffered packets via the callback in one call,
 * then sleeps until the next batch — dramatically reducing CPU vs busy-polling.
 *
 * Timestamps come directly from pcap (HOST_HIPREC when available).
 * The BPF kernel filter ensures only SV frames (0x88BA) reach us.
 */
static void capture_thread_func() {
    printf("[capture] Capture thread started (pcap_dispatch mode, timeout=%dms)\n", SV_CAP_TIMEOUT_MS);
    
    g_capture_start_ms = get_time_ms();
    g_stat_received.store(0);
    g_stat_sv.store(0);
    g_stat_dropped.store(0);
    g_stat_bytes.store(0);
    
#ifdef _WIN32
    /* ── Thread priority boost for reliable packet capture ── */
    timeBeginPeriod(1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    printf("[capture] Thread priority: ABOVE_NORMAL\n");
    printf("[capture] Using direct pcap timestamps (type=%s, precision=%s)\n",
           g_tstamp_type_name,
           g_tstamp_nano_active ? "nano" : "micro");
#endif
    
    /* Start the drain thread (reads SPSC → analysis → display buffer) */
    sv_highperf_start_drain();
    
    while (g_capturing.load(std::memory_order_relaxed)) {
#ifdef _WIN32
        /* pcap_dispatch: process all buffered packets via callback, then return.
         * cnt=-1: process all packets from one buffer read.
         * Blocks up to SV_CAP_TIMEOUT_MS if no packets are available. */
        int res = g_dispatch(g_handle, -1, capture_dispatch_cb, nullptr);
        
        if (res == -2) {
            printf("[capture] pcap breakloop\n");
            break;
        } else if (res < 0) {
            printf("[capture] pcap_dispatch error: %d\n", res);
            break;
        }
        /* res == 0 means timeout (no packets) — loop continues */
#else
        int res = pcap_dispatch(g_handle, -1, capture_dispatch_cb, nullptr);

        if (res == PCAP_ERROR_BREAK) {
            break;
        } else if (res < 0) {
            printf("[capture] pcap_dispatch error: %d — %s\n", res, pcap_geterr(g_handle));
            break;
        } else if (res == 0) {
            /* No packets — yield CPU instead of spinning */
            std::this_thread::sleep_for(std::chrono::milliseconds(SV_CAP_TIMEOUT_MS));
        }
#endif
    }
    
    /* Stop drain thread (flushes remaining SPSC data) */
    sv_highperf_stop_drain();
#ifdef _WIN32
    /* ── Restore thread priority ── */
    timeEndPeriod(1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    
    if (g_pcap_stats && g_handle) {
        struct pcap_stat ps;
        if (g_pcap_stats(g_handle, &ps) == 0) {
            g_stat_dropped.store(ps.ps_drop);
        }
    }
#else
    if (g_handle) {
        struct pcap_stat ps;
        if (pcap_stats(g_handle, &ps) == 0) {
            g_stat_dropped.store(ps.ps_drop);
        }
    }
#endif
    
    printf("[capture] Capture thread stopped. Received: %llu, SV: %llu, Dropped: %llu\n",
           (unsigned long long)g_stat_received.load(),
           (unsigned long long)g_stat_sv.load(),
           (unsigned long long)g_stat_dropped.load());
}

/*============================================================================
 * Capture Start / Stop
 *============================================================================*/

int sv_capture_start(void) {
    if (!g_handle) {
        snprintf(g_error, sizeof(g_error), "No interface open. Call sv_capture_open() first.");
        printf("[capture] ERROR: %s\n", g_error);
        return -1;
    }
    
    if (g_capturing.load()) {
        printf("[capture] Already capturing\n");
        return 0; /* Already running */
    }
    
    g_capturing.store(true);
    g_capture_thread = std::thread(capture_thread_func);
    
    printf("[capture] Capture started\n");
    return 0;
}

int sv_capture_stop(void) {
    if (!g_capturing.load()) {
        return -1; /* Not capturing */
    }
    
    printf("[capture] Stopping capture...\n");
    g_capturing.store(false);
    
    /* Signal pcap to break out of any blocking read */
#ifdef _WIN32
    if (g_breakloop && g_handle) g_breakloop(g_handle);
#else
    if (g_handle) pcap_breakloop(g_handle);
#endif
    
    /* Wait for capture thread to finish */
    if (g_capture_thread.joinable()) {
        g_capture_thread.join();
    }
    
    printf("[capture] Capture stopped\n");
    return 0;
}

int sv_capture_is_running(void) {
    return g_capturing.load() ? 1 : 0;
}

/*============================================================================
 * Statistics
 *============================================================================*/

void sv_capture_get_stats(SvCaptureStats *stats) {
    if (!stats) return;
    
    stats->packetsReceived = g_stat_received.load();
    stats->packetsSV = g_stat_sv.load();
    stats->packetsDropped = g_stat_dropped.load();
    stats->bytesReceived = g_stat_bytes.load();
    stats->captureStartTime = g_capture_start_ms;
    stats->captureElapsedMs = g_capturing.load() ? (get_time_ms() - g_capture_start_ms) : 0;
    stats->isCapturing = g_capturing.load() ? 1 : 0;
}

const char* sv_capture_get_stats_json(void) {
    SvCaptureStats stats;
    sv_capture_get_stats(&stats);
    
    /* Get high-perf pipeline stats */
    SvHighPerfStats hp;
    sv_highperf_get_stats(&hp);
    
    snprintf(g_json_buf, CAP_JSON_BUF_SIZE,
        "{\"packetsReceived\":%llu,\"packetsSV\":%llu,\"packetsDropped\":%llu,"
        "\"bytesReceived\":%llu,\"captureElapsedMs\":%llu,\"isCapturing\":%s,"
        "\"captureRatePps\":%.0f,\"throughputMbps\":%.2f,"
        "\"spscDropped\":%llu,\"spscReadLag\":%llu,"
        "\"drainTotal\":%llu,\"drainBatchAvg\":%llu}",
        (unsigned long long)stats.packetsReceived,
        (unsigned long long)stats.packetsSV,
        (unsigned long long)stats.packetsDropped,
        (unsigned long long)stats.bytesReceived,
        (unsigned long long)stats.captureElapsedMs,
        stats.isCapturing ? "true" : "false",
        hp.captureRatePps,
        hp.throughputMbps,
        (unsigned long long)hp.spscDropped,
        (unsigned long long)hp.spscReadLag,
        (unsigned long long)hp.drainTotal,
        (unsigned long long)hp.drainBatchAvg);
    
    return g_json_buf;
}

const char* sv_capture_list_interfaces_json(void) {
    SvCaptureInterface interfaces[SV_CAP_MAX_INTERFACES];
    int count = sv_capture_list_interfaces(interfaces, SV_CAP_MAX_INTERFACES);
    
    size_t pos = 0;
    char* buf = g_json_buf;
    size_t bufLen = CAP_JSON_BUF_SIZE;
    
    pos += snprintf(buf + pos, bufLen - pos, "{\"interfaces\":[");
    
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            if (i > 0) pos += snprintf(buf + pos, bufLen - pos, ",");
            
            /* Escape backslashes in the device name for JSON */
            char escaped_name[SV_CAP_MAX_NAME * 2];
            size_t j = 0;
            for (size_t k = 0; interfaces[i].name[k] && j < sizeof(escaped_name) - 2; k++) {
                if (interfaces[i].name[k] == '\\' || interfaces[i].name[k] == '"') {
                    escaped_name[j++] = '\\';
                }
                escaped_name[j++] = interfaces[i].name[k];
            }
            escaped_name[j] = '\0';
            
            pos += snprintf(buf + pos, bufLen - pos,
                "{\"name\":\"%s\",\"description\":\"%s\",\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"has_mac\":%s}",
                escaped_name,
                interfaces[i].description,
                interfaces[i].mac[0], interfaces[i].mac[1], interfaces[i].mac[2],
                interfaces[i].mac[3], interfaces[i].mac[4], interfaces[i].mac[5],
                interfaces[i].has_mac ? "true" : "false");
            
            if (pos >= bufLen - 256) break; /* Safety margin */
        }
    }
    
    pos += snprintf(buf + pos, bufLen - pos, "]}");
    
    return g_json_buf;
}

/*============================================================================
 * Timestamp Info (for frontend precision indicator)
 *============================================================================*/

static char g_tstamp_json_buf[512];

const char* sv_capture_get_timestamp_info_json(void) {
    /*
     * Returns JSON describing the active timestamp configuration:
     *   tstampType:       0=HOST, 2=HOST_HIPREC, 3=ADAPTER
     *   tstampTypeName:   "host", "host_hiprec", "adapter"
     *   tstampPrecision:  0=MICRO, 1=NANO
     *   nanoActive:       true if nanosecond precision is active
     *   isHardware:       true if ADAPTER timestamp type is active
     *   method:           "pcap" (direct pcap timestamp, no QPC overlay)
     */
    snprintf(g_tstamp_json_buf, sizeof(g_tstamp_json_buf),
        "{\"tstampType\":%d,\"tstampTypeName\":\"%s\","
        "\"tstampPrecision\":%d,\"nanoActive\":%s,"
        "\"isHardware\":%s,\"method\":\"pcap\"}",
        g_tstamp_type,
        g_tstamp_type_name,
        g_tstamp_precision,
        g_tstamp_nano_active ? "true" : "false",
        (g_tstamp_type == SV_PCAP_TSTAMP_ADAPTER) ? "true" : "false");
    
    return g_tstamp_json_buf;
}

/*============================================================================
 * Error Handling
 *============================================================================*/

const char* sv_capture_get_error(void) {
    return g_error;
}

} /* extern "C" */
