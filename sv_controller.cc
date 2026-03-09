/**
 * @file sv_controller.cc
 * @brief Implementation of SharedBuffer + SvController + Multi-Publisher FFI
 *
 * This is the core of the multi-publisher architecture:
 *
 *   1. SharedBuffer::buildFromPublishers()
 *      - Takes all publishers' internal buffers
 *      - Merges into one sorted, interleaved schedule
 *      - Staggered timestamps so packets interleave evenly
 *
 *   2. SvController
 *      - Creates/manages SvPublisherInstance objects
 *      - On startAll(): prebuild → merge → spawn writer thread
 *      - Writer thread iterates the SharedBuffer, sends via npcap
 *
 *   3. FFI functions (extern "C")
 *      - sv_mp_* functions for Rust/Tauri to call
 *      - Complete lifecycle: add → configure → set equations → start → stop
 *
 * Architecture flow:
 *   UI → Tauri IPC → Rust FFI → sv_mp_* → SvController → SharedBuffer → npcap
 */

#include "../include/sv_controller.h"
#include "../include/npcap_transmitter.h"
#include "../include/sv_stats.h"

#include <cstdio>
#include <cstring>
#include <chrono>
#include <cmath>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")
#else
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#endif

/* Forward declaration: single-publisher running check (sv_native_refactored.cc) */
extern "C" int npcap_publisher_is_running(void);

/*============================================================================
 * SharedBuffer Implementation
 *============================================================================*/

void SharedBuffer::clear()
{
    m_schedule.clear();
    m_cycleDuration_us = 0;
}

void SharedBuffer::buildFromPublishers(
    const std::vector<std::unique_ptr<SvPublisherInstance>>& publishers)
{
    m_schedule.clear();
    m_cycleDuration_us = 0;

    /* Count READY publishers and total frames */
    int readyCount = 0;
    size_t totalFrames = 0;
    for (const auto& pub : publishers) {
        if (pub->getState() == SvPublisherInstance::READY) {
            totalFrames += (size_t)pub->getFrameCount();
            readyCount++;
        }
    }

    if (readyCount == 0 || totalFrames == 0) {
        printf("[shared-buffer] No ready publishers\n");
        return;
    }

    m_schedule.reserve(totalFrames);

    /*
     * Stagger publishers evenly across time.
     *
     * If Publisher 1 sends every 250µs and Publisher 2 sends every 250µs,
     * we stagger Publisher 2 by 125µs so the combined timeline is:
     *
     *   t=  0µs: P1 frame 0
     *   t=125µs: P2 frame 0
     *   t=250µs: P1 frame 1
     *   t=375µs: P2 frame 1
     *   ...
     *
     * This distributes load evenly and avoids packet bursts.
     */

    /* Find the shortest interval (for stagger calculation) */
    uint64_t minInterval_us = UINT64_MAX;
    for (const auto& pub : publishers) {
        if (pub->getState() != SvPublisherInstance::READY) continue;
        uint64_t pps = pub->getPacketsPerSec();
        if (pps == 0) continue;
        uint64_t interval = 1000000ULL / pps;
        if (interval < minInterval_us) minInterval_us = interval;
    }
    if (minInterval_us == UINT64_MAX) minInterval_us = 250;

    uint64_t staggerStep = minInterval_us / (uint64_t)readyCount;
    int pubIndex = 0;

    for (const auto& pub : publishers) {
        if (pub->getState() != SvPublisherInstance::READY) continue;

        uint64_t pps = pub->getPacketsPerSec();
        uint64_t interval_us = (pps > 0) ? (1000000ULL / pps) : 250;
        uint64_t offset_us = (uint64_t)pubIndex * staggerStep;

        for (int i = 0; i < pub->getFrameCount(); i++) {
            ScheduleEntry entry;
            entry.timestamp_us = offset_us + (uint64_t)i * interval_us;
            entry.framePtr     = pub->getFrame(i);
            entry.frameLen     = (uint16_t)pub->getFrameLen(i);
            entry.publisherId  = pub->getId();
            m_schedule.push_back(entry);

            /* Track max timestamp for cycle duration */
            if (entry.timestamp_us + interval_us > m_cycleDuration_us)
                m_cycleDuration_us = entry.timestamp_us + interval_us;
        }

        pubIndex++;
    }

    /* Sort by timestamp — this creates the interleaved playback order */
    std::sort(m_schedule.begin(), m_schedule.end(),
        [](const ScheduleEntry& a, const ScheduleEntry& b) {
            if (a.timestamp_us != b.timestamp_us)
                return a.timestamp_us < b.timestamp_us;
            return a.publisherId < b.publisherId; /* stable tie-break */
        });

    printf("[shared-buffer] Built schedule: %zu entries from %d publishers, "
           "cycle: %llu us\n",
           m_schedule.size(), readyCount,
           (unsigned long long)m_cycleDuration_us);
}

/*============================================================================
 * SvController — Singleton
 *============================================================================*/

SvController& SvController::instance()
{
    static SvController s_instance;
    return s_instance;
}

SvController::SvController()
{
    m_errorBuf[0] = '\0';
}

SvController::~SvController()
{
    stopAll();
}

/*============================================================================
 * Publisher Management
 *============================================================================*/

uint32_t SvController::addPublisher()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    uint32_t id = m_nextId++;
    auto pub = std::make_unique<SvPublisherInstance>(id);
    m_publishers.push_back(std::move(pub));

    printf("[controller] Added publisher %u (total: %zu)\n",
           id, m_publishers.size());
    return id;
}

int SvController::removePublisher(uint32_t id)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_running.load()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf),
                 "Cannot remove publisher while running");
        return -1;
    }

    for (auto it = m_publishers.begin(); it != m_publishers.end(); ++it) {
        if ((*it)->getId() == id) {
            printf("[controller] Removed publisher %u\n", id);
            m_publishers.erase(it);
            return 0;
        }
    }

    snprintf(m_errorBuf, sizeof(m_errorBuf),
             "Publisher %u not found", id);
    return -1;
}

int SvController::removeAllPublishers()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_running.load()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf),
                 "Cannot remove publishers while running");
        return -1;
    }

    size_t count = m_publishers.size();
    m_publishers.clear();
    m_nextId = 1;  /* Reset ID counter for clean session */
    m_sharedBuffer.clear();

    printf("[controller] Removed all %zu publisher(s), ID counter reset\n",
           count);
    return 0;
}

SvPublisherInstance* SvController::getPublisher(uint32_t id)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return findPublisher(id);
}

SvPublisherInstance* SvController::findPublisher(uint32_t id)
{
    for (auto& pub : m_publishers) {
        if (pub->getId() == id) return pub.get();
    }
    return nullptr;
}

uint32_t SvController::getPublisherCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (uint32_t)m_publishers.size();
}

/*============================================================================
 * Publisher Configuration (convenience wrappers)
 *============================================================================*/

int SvController::configurePublisher(uint32_t id, const PublisherConfig& config)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto* pub = findPublisher(id);
    if (!pub) {
        snprintf(m_errorBuf, sizeof(m_errorBuf), "Publisher %u not found", id);
        return -1;
    }
    return pub->configure(config);
}

int SvController::setPublisherEquations(uint32_t id, const char* equations)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto* pub = findPublisher(id);
    if (!pub) {
        snprintf(m_errorBuf, sizeof(m_errorBuf), "Publisher %u not found", id);
        return -1;
    }
    return pub->setEquations(equations);
}

/*============================================================================
 * Global Settings
 *============================================================================*/

int SvController::setSendMode(int mode)
{
    if (mode < 0 || mode > 3) {
        snprintf(m_errorBuf, sizeof(m_errorBuf),
                 "Invalid send mode: %d (0=auto, 1=batch, 2=immediate, 3=usb)", mode);
        return -1;
    }
    if (m_running.load()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf),
                 "Cannot change send mode while running");
        return -1;
    }
    m_sendMode = mode;
    const char* names[] = {"AUTO", "SendQueue (batch)", "SendPacket (immediate)", "USB-Optimized (spin+gap)"};
    printf("[controller] Send mode: %s\n", names[mode]);
    return 0;
}

int SvController::setDuration(uint32_t seconds, bool repeat,
                               bool infinite, uint32_t count)
{
    m_durationSeconds = seconds;
    m_repeatEnabled   = repeat;
    m_repeatInfinite  = infinite;
    m_repeatCount     = count;
    m_repeatCycle.store(0);
    return 0;
}

uint32_t SvController::getRemainingSeconds() const
{
    if (m_durationSeconds == 0 || !m_running.load()) return m_durationSeconds;

    uint64_t elapsed = npcap_stats_get_time_ms() - m_startTimeMs.load();
    uint64_t total   = (uint64_t)m_durationSeconds * 1000ULL;
    return (elapsed >= total) ? 0 : (uint32_t)((total - elapsed) / 1000);
}

bool SvController::checkDurationElapsed() const
{
    if (m_durationSeconds == 0) return false;
    uint64_t elapsed = npcap_stats_get_time_ms() - m_startTimeMs.load();
    return elapsed >= (uint64_t)m_durationSeconds * 1000ULL;
}

/*============================================================================
 * Thread Priority Helpers
 *============================================================================*/

void SvController::elevateThreadPriority()
{
#ifdef _WIN32
    timeBeginPeriod(1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    SetThreadAffinityMask(GetCurrentThread(), 1ULL << 0);
    printf("[controller] Writer thread: TIME_CRITICAL, core 0\n");
#else
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &param) == 0) {
        printf("[controller] Writer thread: SCHED_FIFO priority %d\n", param.sched_priority);
    } else {
        nice(-20);
        printf("[controller] Writer thread: nice(-20) fallback\n");
    }
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
#endif
#endif
}

void SvController::restoreThreadPriority()
{
#ifdef _WIN32
    timeEndPeriod(1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SetThreadAffinityMask(GetCurrentThread(),
                          (1ULL << si.dwNumberOfProcessors) - 1);
#else
    struct sched_param param;
    param.sched_priority = 0;
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &param);
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    for (long i = 0; i < nprocs; i++) CPU_SET(i, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
#endif
#endif
}

/*============================================================================
 * Lifecycle: startAll / stopAll
 *============================================================================*/

int SvController::startAll()
{
    if (m_running.load()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf), "Already running");
        return -1;
    }
    if (npcap_publisher_is_running()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf),
                 "Single-publisher is already running. Stop it before using multi-publisher.");
        return -1;
    }
    if (!npcap_is_open()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf), "No network interface open");
        return -1;
    }

    /* Safety: join any leftover writer thread from a previous session
     * that ended naturally (duration elapsed, m_running set to false
     * by the writer loop itself). Without this, assigning a new thread
     * to m_writerThread would crash (std::terminate). */
    if (m_writerThread.joinable()) {
        printf("[controller] Joining leftover writer thread before restart\n");
        m_writerThread.join();
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_publishers.empty()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf), "No publishers added");
        return -1;
    }

    printf("[controller] ═══════════════════════════════════════════\n");
    printf("[controller] Starting %zu publisher(s)...\n", m_publishers.size());

    /*
     * STEP 1: Pre-build frames for each publisher (SEQUENTIAL)
     * Each publisher sets the global encoder config and builds its frames.
     * Sequential execution avoids encoder state conflicts.
     */
    for (auto& pub : m_publishers) {
        if (pub->getState() < SvPublisherInstance::CONFIGURED) {
            printf("[controller] WARNING: publisher %u not configured, skipping\n",
                   pub->getId());
            continue;
        }
        int ret = pub->prebuildFrames();
        if (ret != 0) {
            snprintf(m_errorBuf, sizeof(m_errorBuf),
                     "Publisher %u: prebuild failed: %s",
                     pub->getId(), pub->getLastError());
            return -1;
        }
    }

    /*
     * STEP 2: Build SharedBuffer (merged interleaved schedule)
     * Merges all publishers' internal buffers into one sorted timeline.
     */
    m_sharedBuffer.buildFromPublishers(m_publishers);

    if (m_sharedBuffer.empty()) {
        snprintf(m_errorBuf, sizeof(m_errorBuf),
                 "Shared buffer is empty — no frames built");
        return -1;
    }

    /*
     * STEP 3: Start writer thread
     */
    m_startTimeMs.store(npcap_stats_get_time_ms());
    m_durationComplete.store(false);
    m_repeatCycle.store(0);
    m_running.store(true);

    m_writerThread = std::thread(&SvController::writerLoop, this);

    printf("[controller] Writer thread started\n");
    printf("[controller] ═══════════════════════════════════════════\n");
    return 0;
}

int SvController::stopAll()
{
    bool wasRunning = m_running.exchange(false);

    /* ALWAYS join the writer thread if joinable — even if m_running was
     * already false (e.g., duration elapsed and the writer loop ended
     * naturally).  Without this, the next startAll() would assign a new
     * std::thread to a still-joinable m_writerThread, which calls
     * std::terminate() and crashes (STATUS_STACK_BUFFER_OVERRUN). */
    if (m_writerThread.joinable()) {
        printf("[controller] Joining writer thread...\n");
        m_writerThread.join();
    }

    m_sharedBuffer.clear();

    /* Defense-in-depth: clear all publishers so stale state never persists.
     * The caller always does removeAll + add + configure before each start,
     * so keeping old publishers serves no purpose and risks accumulation bugs. */
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_publishers.clear();
        m_nextId = 1;
    }

    if (wasRunning)
        printf("[controller] Stopped (publishers cleared)\n");
    else
        printf("[controller] Cleaned up stale session (publishers cleared)\n");
    return 0;
}

int SvController::resetAll()
{
    printf("[controller] ═══════════════════════════════════════════\n");
    printf("[controller] FULL RESET — clearing all state\n");

    /* 1. Stop transmission and ALWAYS join thread (even if naturally ended) */
    m_running.store(false);
    if (m_writerThread.joinable())
        m_writerThread.join();

    /* 2. Clear shared buffer */
    m_sharedBuffer.clear();

    /* 3. Clear all publishers (frees frame caches) */
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_publishers.clear();
        m_nextId = 1;
    }

    /* 4. Reset global settings to defaults */
    m_sendMode         = 0;
    m_durationSeconds  = 0;
    m_repeatEnabled    = false;
    m_repeatInfinite   = false;
    m_repeatCount      = 0;
    m_repeatCycle.store(0);
    m_durationComplete.store(false);
    m_startTimeMs.store(0);
    m_usbPadSize       = 0;
    m_usbMinGapUs      = 0;
    m_errorBuf[0] = '\0';

    /* 5. Reset stats */
    npcap_stats_reset();

    /* 6. Stop single-publisher if it was running */
    extern int npcap_publisher_stop(void);
    npcap_publisher_stop();

    printf("[controller] Reset complete — all memory freed, all state cleared\n");
    printf("[controller] ═══════════════════════════════════════════\n");
    return 0;
}

/*============================================================================
 * Writer Thread — Entry Point
 * Dispatches to batch or immediate mode based on sendMode setting.
 *============================================================================*/

void SvController::writerLoop()
{
    bool useBatch = false;

    switch (m_sendMode) {
    case 1: /* Force batch */
        useBatch = npcap_sendqueue_available();
        if (!useBatch)
            printf("[controller] WARNING: batch mode requested but sendqueue "
                   "not available, falling back to immediate\n");
        break;
    case 2: /* Force immediate */
        useBatch = false;
        break;
    case 3: /* USB-Optimized: force immediate + spin pacing */
        useBatch = false;
        break;
    case 0: /* Auto */
    default:
        useBatch = npcap_sendqueue_available();
        break;
    }

    if (useBatch)
        writerLoopBatch();
    else
        writerLoopImmediate();
}

/*============================================================================
 * Writer Loop — Batch Mode (sendqueue)
 *
 * Two-tier strategy (same as original single-publisher):
 *
 * TIER 1 — PRECISE (aggregate ≤4800 pps)
 *   1 pkt/sendqueue, sync=1.
 *
 * TIER 2 — HIGH-SPEED (aggregate >4800 pps)
 *   Multi-pkt/sendqueue, sync=0 + QPC spin-wait pacing.
 *============================================================================*/

void SvController::writerLoopBatch()
{
    printf("[controller] Writer: BATCH mode (sendqueue)\n");

batch_loop_start:
    elevateThreadPriority();
    npcap_stats_reset();
    npcap_stats_session_start();

    const size_t schedSize    = m_sharedBuffer.size();
    const uint64_t cycle_us   = m_sharedBuffer.getCycleDuration();
    const size_t frameLen     = m_sharedBuffer[0].frameLen; /* approx, for sizing */

    /* Aggregate rate across all publishers */
    uint64_t aggregate_pps = (cycle_us > 0)
        ? (schedSize * 1000000ULL / cycle_us) : schedSize;

    /* Wire time per frame at 1 Gbps */
    double wire_time_us = (double)(frameLen + 20) * 8.0 / 1000.0;

    printf("[controller] Schedule: %zu entries, cycle: %llu us, "
           "aggregate: %llu pps\n",
           schedSize, (unsigned long long)cycle_us,
           (unsigned long long)aggregate_pps);

    uint64_t totalPackets = 0;

    /*--------------------------------------------------------------
     * TIER 1 — PRECISE (≤4800 pps aggregate)
     *--------------------------------------------------------------*/
    if (aggregate_pps <= 4800) {
        printf("[controller] Tier: PRECISE (1 pkt/queue, sync=1)\n");

        while (m_running.load() && !checkDurationElapsed()) {
            uint64_t ts_accum = 0;

            for (size_t i = 0; i < schedSize; i++) {
                if (!m_running.load() || checkDurationElapsed()) break;

                const ScheduleEntry& e = m_sharedBuffer[i];
                unsigned int qsize = (unsigned int)(e.frameLen + 24 + 4096);
                void* q = npcap_queue_create(qsize);
                if (!q) continue;

                npcap_queue_add(q, e.framePtr, e.frameLen, ts_accum);

                /* Interval to NEXT entry */
                if (i + 1 < schedSize) {
                    ts_accum += m_sharedBuffer[i + 1].timestamp_us
                              - e.timestamp_us;
                } else {
                    /* Wrap: end of cycle → start of next cycle */
                    ts_accum += cycle_us - e.timestamp_us;
                }

                unsigned int sent = npcap_queue_transmit(q, 1);
                if (sent > 0) {
                    totalPackets++;
                    npcap_stats_record_packet(e.frameLen);
                }
                npcap_queue_destroy(q);
            }
        }
    }
    /*--------------------------------------------------------------
     * TIER 2 — HIGH-SPEED (>4800 pps aggregate)
     *--------------------------------------------------------------*/
    else {
        /* Adaptive batch: target ~500µs of wire time per burst */
        uint64_t batchSize = (uint64_t)(500.0 / wire_time_us);
        if (batchSize < 50)   batchSize = 50;
        if (batchSize > 5000) batchSize = 5000;
        if (batchSize > schedSize) batchSize = schedSize;

        double batchInterval_us = (double)batchSize * 1000000.0
                                  / (double)aggregate_pps;
        auto batchDuration = std::chrono::nanoseconds(
            (int64_t)(batchInterval_us * 1000.0));

        printf("[controller] Tier: HIGH-SPEED (batch=%llu, sync=0, "
               "QPC pacing)\n", (unsigned long long)batchSize);

        unsigned int qmemsize =
            (unsigned int)(batchSize * (frameLen + 24) + 4096);
        auto nextBatch = std::chrono::high_resolution_clock::now();
        uint64_t batchCount = 0;
        uint64_t schedIdx = 0;

        while (m_running.load() && !checkDurationElapsed()) {
            void* q = npcap_queue_create(qmemsize);
            if (!q) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }

            for (uint64_t b = 0; b < batchSize; b++) {
                const ScheduleEntry& e =
                    m_sharedBuffer[schedIdx % schedSize];
                npcap_queue_add(q, e.framePtr, e.frameLen, 0);
                schedIdx++;
            }

            unsigned int sent = npcap_queue_transmit(q, 0);
            if (sent > 0) {
                uint32_t pkts = sent / (uint32_t)frameLen;
                totalPackets += pkts;
                for (uint32_t p = 0; p < pkts; p++)
                    npcap_stats_record_packet(frameLen);
            }
            npcap_queue_destroy(q);

            /* QPC spin-wait for pacing */
            nextBatch += batchDuration;
            while (std::chrono::high_resolution_clock::now() < nextBatch)
                spinPause();

            /* Re-anchor every 200 batches to prevent drift */
            batchCount++;
            if ((batchCount % 200) == 0)
                nextBatch = std::chrono::high_resolution_clock::now();
        }
    }

    restoreThreadPriority();

    /* Handle repeat — use ITERATIVE loop, not recursion.
     * Recursion would stack frames on every cycle and eventually
     * overflow the thread stack (STATUS_STACK_BUFFER_OVERRUN). */
    if (checkDurationElapsed() && m_repeatEnabled) {
        m_repeatCycle.fetch_add(1);
        uint32_t cycle = m_repeatCycle.load();
        if (m_repeatInfinite || cycle < m_repeatCount) {
            printf("[controller] Repeat cycle %u\n", cycle + 1);
            m_startTimeMs.store(npcap_stats_get_time_ms());
            m_durationComplete.store(false);
            goto batch_loop_start;  /* iterate, don't recurse */
        }
    }

    npcap_stats_session_end();

    if (checkDurationElapsed()) {
        m_durationComplete.store(true);
        m_running.store(false);
    }

    printf("[controller] Batch writer complete: %llu packets\n",
           (unsigned long long)totalPackets);
}

/*============================================================================
 * Writer Loop — Immediate Mode (pcap_sendpacket per packet)
 *
 * Pacing modes (same as original single-publisher):
 *   ≤4800 pps: SLEEP + SPIN hybrid
 *   ≤50000 pps: pure SPIN (_mm_pause)
 *   >50000 pps: no pacing (max throughput)
 *============================================================================*/

void SvController::writerLoopImmediate()
{
    printf("[controller] Writer: IMMEDIATE mode (pcap_sendpacket)\n");

immediate_loop_start:
    elevateThreadPriority();
    npcap_stats_reset();
    npcap_stats_session_start();

    const size_t schedSize  = m_sharedBuffer.size();
    const uint64_t cycle_us = m_sharedBuffer.getCycleDuration();

    uint64_t aggregate_pps = (cycle_us > 0)
        ? (schedSize * 1000000ULL / cycle_us) : schedSize;

    /* Choose pacing */
    enum Pacing { SLEEP, SPIN, NONE };
    Pacing pacing;
    bool usbMode = (m_sendMode == 3);

    if (usbMode)                     pacing = SPIN;  /* USB: always spin */
    else if (aggregate_pps <= 4800)  pacing = SLEEP;
    else if (aggregate_pps <= 50000) pacing = SPIN;
    else                             pacing = NONE;

    const char* pacingNames[] = {"SLEEP+SPIN", "SPIN", "NONE"};
    printf("[controller] Pacing: %s, aggregate: %llu pps%s\n",
           pacingNames[pacing], (unsigned long long)aggregate_pps,
           usbMode ? " [USB-OPTIMIZED]" : "");

    int usbPadSize = m_usbPadSize;
    int usbGapUs = (m_usbMinGapUs > 0) ? m_usbMinGapUs : 130;
    if (usbMode) {
        printf("[controller] USB-OPTIMIZED: gap=%d us", usbGapUs);
        if (usbPadSize > 0)
            printf(", padding=%d bytes", usbPadSize);
        printf("\n");
    }

    uint64_t totalPackets  = 0;
    uint64_t totalFailures = 0;
    uint64_t schedIdx      = 0;

    /* Calculate average interval between consecutive schedule entries */
    double avg_interval_us = (aggregate_pps > 0)
        ? (1000000.0 / (double)aggregate_pps) : 250.0;
    auto intervalDur = std::chrono::nanoseconds(
        (int64_t)(avg_interval_us * 1000.0));

    /* Epoch-based absolute scheduling (industry standard).
     *
     * target[N] = epoch + N * interval
     *
     * This ensures the average packet rate is EXACTLY correct regardless
     * of how long each pcap_sendpacket() call takes.
     *
     * If pcap_sendpacket takes longer than the interval, we fall behind
     * schedule. To handle this:
     *   - Small lag: send next packet immediately (natural catch-up)
     *   - Large lag (>3 intervals behind): re-anchor epoch to prevent
     *     unbounded bursts of back-to-back packets
     *
     * This is the same approach used by tcpreplay, Linux pktgen, and
     * professional traffic generators (DPDK TRex, MoonGen, etc.).
     */
    auto epoch = std::chrono::high_resolution_clock::now();
    uint64_t pktNum = 0;

    while (m_running.load() && !checkDurationElapsed()) {
        const ScheduleEntry& e = m_sharedBuffer[schedIdx % schedSize];

        int result;
        if (usbMode && usbPadSize > 0 && usbPadSize > (int)e.frameLen) {
            result = npcap_send_packet_padded(e.framePtr, e.frameLen, (size_t)usbPadSize);
        } else {
            result = npcap_send_packet(e.framePtr, e.frameLen);
        }
        if (result == 0) {
            totalPackets++;
            npcap_stats_record_packet(e.frameLen);
        } else {
            totalFailures++;
            npcap_stats_record_failure();
        }

        schedIdx++;
        pktNum++;

        if (pacing == NONE)
            continue;

        /* Absolute target for the NEXT packet */
        auto target = epoch + pktNum * intervalDur;
        auto now    = std::chrono::high_resolution_clock::now();

        if (target <= now) {
            /* Behind schedule — check how far */
            auto behind = std::chrono::duration_cast<
                std::chrono::nanoseconds>(now - target);
            if (behind > intervalDur) {
                /* Behind by >1 interval — re-anchor to prevent burst.
                 * Allows at most 1 catch-up packet (small lag < 1 interval)
                 * but prevents back-to-back bursts of 3-4 packets that
                 * appear as 0.000000 deltas in Wireshark. */
                epoch  = now;
                pktNum = 0;
            }

            /* USB mode: even when behind, enforce minimum gap between
             * sends so the USB host controller doesn't batch packets
             * into the same microframe (125µs). Configurable gap. */
            if (usbMode) {
                auto minTarget = now + std::chrono::microseconds(usbGapUs);
                while (std::chrono::high_resolution_clock::now() < minTarget)
                    spinPause();
            }
            continue;
        }

        /* Ahead of schedule — pace to exact target */
        switch (pacing) {
        case SLEEP: {
            auto remaining = std::chrono::duration_cast<
                std::chrono::microseconds>(target - now);
            if (remaining.count() > 80)
                std::this_thread::sleep_for(
                    remaining - std::chrono::microseconds(80));
            while (std::chrono::high_resolution_clock::now() < target)
                spinPause();
            break;
        }
        case SPIN:
            while (std::chrono::high_resolution_clock::now() < target)
                spinPause();
            break;
        default:
            break;
        }
    }

    restoreThreadPriority();

    /* Handle repeat — use ITERATIVE loop, not recursion.
     * Recursion would stack frames on every cycle and eventually
     * overflow the thread stack (STATUS_STACK_BUFFER_OVERRUN). */
    if (checkDurationElapsed() && m_repeatEnabled) {
        m_repeatCycle.fetch_add(1);
        uint32_t cycle = m_repeatCycle.load();
        if (m_repeatInfinite || cycle < m_repeatCount) {
            printf("[controller] Repeat cycle %u\n", cycle + 1);
            m_startTimeMs.store(npcap_stats_get_time_ms());
            m_durationComplete.store(false);
            goto immediate_loop_start;  /* iterate, don't recurse */
        }
    }

    npcap_stats_session_end();

    if (checkDurationElapsed()) {
        m_durationComplete.store(true);
        m_running.store(false);
    }

    printf("[controller] Immediate writer complete: %llu sent, %llu failed\n",
           (unsigned long long)totalPackets,
           (unsigned long long)totalFailures);
}

/*============================================================================
 * FFI Exports — Multi-Publisher API for Rust/Tauri
 *
 * Naming: sv_mp_*  (mp = multi-publisher)
 * All functions delegate to SvController::instance()
 *============================================================================*/

extern "C" {

/*--- Publisher Management ---*/

uint32_t sv_mp_add_publisher(void)
{
    return SvController::instance().addPublisher();
}

int sv_mp_remove_publisher(uint32_t id)
{
    return SvController::instance().removePublisher(id);
}

int sv_mp_remove_all_publishers(void)
{
    return SvController::instance().removeAllPublishers();
}

uint32_t sv_mp_get_publisher_count(void)
{
    return SvController::instance().getPublisherCount();
}

/*--- Publisher Configuration ---*/

int sv_mp_configure_publisher(
    uint32_t id,
    const char* svID,
    uint16_t appID,
    uint32_t confRev,
    uint8_t smpSynch,
    const uint8_t* srcMAC,
    const uint8_t* dstMAC,
    int vlanPriority,
    int vlanID,
    uint64_t sampleRate,
    double frequency,
    double voltageAmplitude,
    double currentAmplitude,
    uint8_t asduCount,
    uint8_t channelCount)
{
    PublisherConfig config = {};

    if (svID && strlen(svID) > 0)
        strncpy(config.svID, svID, sizeof(config.svID) - 1);
    else
        strncpy(config.svID, "MU01", sizeof(config.svID) - 1);

    config.appID        = appID;
    config.confRev      = confRev;
    config.smpSynch     = smpSynch;
    if (srcMAC) memcpy(config.srcMAC, srcMAC, 6);
    if (dstMAC) memcpy(config.dstMAC, dstMAC, 6);
    config.vlanPriority = vlanPriority;
    config.vlanID       = vlanID;
    config.sampleRate   = sampleRate;
    config.frequency    = frequency;
    config.voltageAmplitude = voltageAmplitude;
    config.currentAmplitude = currentAmplitude;
    config.asduCount    = asduCount;
    config.channelCount = channelCount;

    return SvController::instance().configurePublisher(id, config);
}

int sv_mp_set_publisher_equations(uint32_t id, const char* equations)
{
    return SvController::instance().setPublisherEquations(id, equations);
}

/*--- Lifecycle ---*/

int sv_mp_start_all(void)
{
    return SvController::instance().startAll();
}

int sv_mp_stop_all(void)
{
    return SvController::instance().stopAll();
}

int sv_mp_reset_all(void)
{
    return SvController::instance().resetAll();
}

int sv_mp_is_running(void)
{
    return SvController::instance().isRunning() ? 1 : 0;
}

/*--- Global Settings ---*/

int sv_mp_set_send_mode(int mode)
{
    return SvController::instance().setSendMode(mode);
}

int sv_mp_get_send_mode(void)
{
    return SvController::instance().getSendMode();
}

int sv_mp_set_duration(uint32_t seconds, int repeat,
                       int infinite, uint32_t count)
{
    return SvController::instance().setDuration(
        seconds, repeat != 0, infinite != 0, count);
}

uint32_t sv_mp_get_remaining_seconds(void)
{
    return SvController::instance().getRemainingSeconds();
}

uint32_t sv_mp_get_current_repeat_cycle(void)
{
    return SvController::instance().getCurrentRepeatCycle();
}

int sv_mp_is_duration_complete(void)
{
    return SvController::instance().isDurationComplete() ? 1 : 0;
}

const char* sv_mp_get_last_error(void)
{
    return SvController::instance().getLastError();
}

void sv_mp_set_usb_pad_size(int bytes)
{
    SvController::instance().setUsbPadSize(bytes);
    printf("[controller] USB pad size set to %d bytes\n",
           SvController::instance().getUsbPadSize());
}

int sv_mp_get_usb_pad_size(void)
{
    return SvController::instance().getUsbPadSize();
}

void sv_mp_set_usb_min_gap_us(int us)
{
    SvController::instance().setUsbMinGapUs(us);
    printf("[controller] USB min gap set to %d us\n",
           SvController::instance().getUsbMinGapUs());
}

int sv_mp_get_usb_min_gap_us(void)
{
    return SvController::instance().getUsbMinGapUs();
}

} /* extern "C" */
