/**
 * @file sv_capture.h
 * @brief SV Packet Capture Layer using Npcap
 * 
 * This module provides raw Ethernet packet capture for receiving
 * IEC 61850-9-2LE Sampled Values frames. It mirrors the DLL loading
 * pattern from the SV Publisher's npcap_transmitter_impl.cc but uses
 * pcap_dispatch for RECEIVING packets instead of sendqueue.
 * 
 * Capture Flow:
 * ```
 * ┌─────────────────────────────────────────────┐
 * │  Network Interface (via Npcap)              │
 * │  EtherType 0x88BA BPF filter (kernel)       │
 * └──────────────┬──────────────────────────────┘
 *                │ pcap_dispatch() callback
 *                ▼
 * ┌─────────────────────────────────────────────┐
 * │  sv_highperf_capture_feed()  [lock-free]    │
 * │  Inline BER decode → SPSC ring push         │
 * └──────────────┬──────────────────────────────┘
 *                │ SPSC ring (1M slots)
 *                ▼
 * ┌─────────────────────────────────────────────┐
 * │  Drain Thread → Analysis → Display Buffer   │
 * └─────────────────────────────────────────────┘
 * ```
 * 
 * Usage:
 *   1. sv_capture_load_dll()        - Load Npcap DLL
 *   2. sv_capture_list_interfaces() - Enumerate NICs
 *   3. sv_capture_open()            - Open selected NIC
 *   4. sv_capture_start()           - Start capture thread
 *   5. sv_capture_stop()            - Stop capture
 *   6. sv_capture_close()           - Close interface
 * 
 * All functions are extern "C" for Tauri FFI compatibility.
 */

#ifndef SV_CAPTURE_H
#define SV_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

#define SV_CAP_MAX_INTERFACES   32      /**< Max interfaces to enumerate */
#define SV_CAP_MAX_NAME         512     /**< Max interface name length */
#define SV_CAP_MAX_DESC         256     /**< Max description length */
#define SV_CAP_SNAPLEN          65536   /**< Capture snapshot length */
#define SV_CAP_PROMISC          1       /**< Enable promiscuous mode */
#define SV_CAP_TIMEOUT_MS       10      /**< Read timeout (ms) for pcap_dispatch — balance latency vs CPU */
#define SV_CAP_BUFFER_SIZE      (10 * 1024 * 1024) /**< Kernel capture buffer: 10 MB */

/*============================================================================
 * Data Structures
 *============================================================================*/

/**
 * @brief Network interface descriptor
 * 
 * Mirrors NpcapInterface from the publisher's npcap_transmitter.h
 */
typedef struct {
    char        name[SV_CAP_MAX_NAME];    /**< pcap device name (e.g., \Device\NPF_{GUID}) */
    char        description[SV_CAP_MAX_DESC]; /**< Friendly description */
    uint8_t     mac[6];                    /**< MAC address */
    uint8_t     has_mac;                   /**< 1 if MAC was resolved */
} SvCaptureInterface;

/**
 * @brief Capture statistics
 */
typedef struct {
    uint64_t    packetsReceived;           /**< Total packets captured */
    uint64_t    packetsSV;                 /**< Packets matching SV EtherType */
    uint64_t    packetsDropped;            /**< Packets dropped by kernel/driver */
    uint64_t    bytesReceived;             /**< Total bytes captured */
    uint64_t    captureStartTime;          /**< Capture start timestamp (ms) */
    uint64_t    captureElapsedMs;          /**< Elapsed capture time (ms) */
    uint8_t     isCapturing;               /**< 1 if capture thread is running */
} SvCaptureStats;

/*============================================================================
 * DLL Management
 *============================================================================*/

/**
 * @brief Load the Npcap DLL dynamically
 * 
 * Loads wpcap.dll from System32\Npcap\ (preferred) or system PATH.
 * Must be called before any other capture function.
 * 
 * @return 1 on success, 0 on failure (call sv_capture_get_error())
 */
int sv_capture_load_dll(void);

/**
 * @brief Check if Npcap DLL is loaded
 * @return 1 if loaded, 0 if not
 */
int sv_capture_dll_loaded(void);

/*============================================================================
 * Interface Management
 *============================================================================*/

/**
 * @brief Enumerate available network interfaces
 * 
 * Lists all network interfaces visible to Npcap, with MAC address
 * resolution via Windows GetAdaptersInfo API.
 * 
 * @param[out] interfaces  Array to fill with interface descriptors
 * @param[in]  max_count   Maximum interfaces to enumerate
 * @return Number of interfaces found, or -1 on error
 */
int sv_capture_list_interfaces(SvCaptureInterface *interfaces, int max_count);

/**
 * @brief Open a network interface for capture
 * 
 * Opens the specified interface in promiscuous mode with the BPF filter
 * "ether proto 0x88ba" to capture only SV frames.
 * 
 * @param[in] device_name  pcap device name (from SvCaptureInterface.name)
 * @return 0 on success, -1 on failure
 */
int sv_capture_open(const char *device_name);

/**
 * @brief Close the currently open interface
 */
void sv_capture_close(void);

/**
 * @brief Check if an interface is currently open
 * @return 1 if open, 0 if not
 */
int sv_capture_is_open(void);

/*============================================================================
 * Capture Control
 *============================================================================*/

/**
 * @brief Start packet capture in a background thread
 * 
 * Spawns a capture thread that calls pcap_next_ex() in a polling loop.
 * Each captured SV packet is fed to sv_highperf_capture_feed() (lock-free).
 * 
 * The subscriber must be initialized before calling this
 * (via sv_subscriber_init).
 * 
 * @return 0 on success, -1 on failure
 */
int sv_capture_start(void);

/**
 * @brief Stop packet capture
 * 
 * Signals the capture thread to stop and waits for it to finish.
 * The interface remains open (can restart capture).
 * 
 * @return 0 on success, -1 if not capturing
 */
int sv_capture_stop(void);

/**
 * @brief Check if capture is currently running
 * @return 1 if capturing, 0 if not
 */
int sv_capture_is_running(void);

/*============================================================================
 * Statistics
 *============================================================================*/

/**
 * @brief Get capture statistics
 * 
 * @param[out] stats  Statistics structure to fill
 */
void sv_capture_get_stats(SvCaptureStats *stats);

/**
 * @brief Get capture statistics as JSON string
 * 
 * @return JSON string (static buffer - copy before next call)
 * 
 * JSON Format:
 * ```json
 * {
 *   "packetsReceived": 12345,
 *   "packetsSV": 12340,
 *   "packetsDropped": 0,
 *   "bytesReceived": 1234567,
 *   "captureElapsedMs": 5000,
 *   "isCapturing": true
 * }
 * ```
 */
const char* sv_capture_get_stats_json(void);

/**
 * @brief Get interface list as JSON string
 * 
 * Convenient for frontend to get interfaces without struct marshalling.
 * 
 * @return JSON string with array of interfaces
 * 
 * JSON Format:
 * ```json
 * {
 *   "interfaces": [
 *     {
 *       "name": "\\Device\\NPF_{GUID}",
 *       "description": "Intel Ethernet",
 *       "mac": "AA:BB:CC:DD:EE:FF",
 *       "has_mac": true
 *     }
 *   ]
 * }
 * ```
 */
const char* sv_capture_list_interfaces_json(void);

/*============================================================================
 * Error Handling
 *============================================================================*/

/**
 * @brief Get last error message
 * @return Static error string
 */
const char* sv_capture_get_error(void);

/**
 * @brief Get timestamp configuration info as JSON
 * 
 * Returns information about the active timestamp type and precision.
 * Used by frontend to display precision indicator badge.
 * 
 * @return JSON string (static buffer - copy before next call)
 * 
 * JSON Format:
 * ```json
 * {
 *   "tstampType": 3,
 *   "tstampTypeName": "adapter",
 *   "tstampPrecision": 1,
 *   "nanoActive": true,
 *   "isHardware": true
 * }
 * ```
 */
const char* sv_capture_get_timestamp_info_json(void);

#ifdef __cplusplus
}
#endif

#endif /* SV_CAPTURE_H */
