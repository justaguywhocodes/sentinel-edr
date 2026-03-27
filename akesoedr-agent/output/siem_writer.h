/*
 * akesoedr-agent/output/siem_writer.h
 * SIEM output writer — HTTP POST NDJSON batches to a configurable endpoint.
 *
 * Features:
 *   - Background worker thread with queue + condition variable
 *   - Batch accumulation with size + time flush triggers
 *   - API key authentication via X-API-Key header
 *   - Spill-to-disk on SIEM unavailability
 *   - Automatic drain of spill file on reconnect
 *
 * P9-T5: SIEM Integration.
 */

#ifndef AKESOEDR_SIEM_WRITER_H
#define AKESOEDR_SIEM_WRITER_H

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include "telemetry.h"

struct AkesoEDRConfig;  /* Forward declaration */

class SiemWriter {
public:
    SiemWriter();
    ~SiemWriter();

    /*
     * Initialize the SIEM writer from configuration.
     * If SIEM output is disabled (siemEnabled = false), this is a no-op
     * and Enqueue() silently discards events.
     */
    bool Init(const AkesoEDRConfig& cfg);

    /*
     * Enqueue an event for SIEM output. Thread-safe.
     * The event is serialized and batched on the worker thread.
     * If SIEM is disabled, this is a no-op.
     */
    void Enqueue(const AKESOEDR_EVENT& evt,
                 const std::wstring& parentImagePath);

    /*
     * Enqueue a pre-formatted NDJSON line for SIEM output. Thread-safe.
     * Used for AV SIEM events that arrive with their own envelope format.
     * If SIEM is disabled, this is a no-op.
     */
    void EnqueueRaw(const std::string& ndjsonLine);

    /*
     * Flush remaining events and shut down the worker thread.
     * Blocks until all queued events are processed or 5 seconds elapse.
     */
    void Shutdown();

    /* Whether SIEM output is enabled and initialized. */
    bool IsEnabled() const { return m_enabled; }

private:
    /* ── Configuration ───────────────────────────────────────────────────── */
    bool        m_enabled;
    std::string m_endpoint;         /* Full URL */
    std::string m_apiKey;
    std::string m_hostname;         /* Cached machine hostname */
    std::string m_agentId;          /* Agent instance GUID */
    UINT32      m_batchSize;
    UINT32      m_flushIntervalSec;
    std::string m_spillPath;        /* Spill file path */
    UINT64      m_spillMaxBytes;

    /* Parsed URL components for WinHTTP */
    std::wstring m_hostW;
    INTERNET_PORT m_port;
    std::wstring m_pathW;
    bool        m_useHttps;

    /* ── Event queue ─────────────────────────────────────────────────────── */
    struct QueueEntry {
        AKESOEDR_EVENT  evt;
        std::wstring    parentImagePath;
        std::string     rawJson;    /* Non-empty = raw passthrough mode */
        bool            isRaw = false;
    };

    std::deque<QueueEntry>  m_queue;
    std::mutex              m_mutex;
    std::condition_variable m_cv;
    bool                    m_shutdown;

    /* ── Worker thread ───────────────────────────────────────────────────── */
    std::thread m_workerThread;
    void WorkerLoop();

    /* ── HTTP ────────────────────────────────────────────────────────────── */
    HINTERNET m_hSession;

    bool HttpPost(const std::string& ndjsonBatch);
    bool ParseEndpointUrl();

    /* ── Spill-to-disk ───────────────────────────────────────────────────── */
    void SpillToDisk(const std::string& ndjsonBatch);
    bool DrainSpillFile();
};

#endif /* AKESOEDR_SIEM_WRITER_H */
