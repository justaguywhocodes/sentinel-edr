/*
 * sentinel-agent/pipeline.h
 * Event processing pipeline for the SentinelPOC agent.
 *
 * Architecture:
 *   Driver port receiver thread  ──┐
 *                                  ├──► EventQueue ──► Processing thread
 *   Pipe server receiver thread(s)─┘
 *
 * The pipeline receives SENTINEL_EVENT from two sources:
 *   1. Driver filter communication port (\SentinelPort)
 *   2. Named pipe from hook DLLs (\\.\pipe\SentinelTelemetry)
 *
 * All events are funneled into a thread-safe EventQueue and consumed
 * by a processing thread (currently logs to file; future phases add
 * rule evaluation and alerting).
 */

#ifndef SENTINEL_PIPELINE_H
#define SENTINEL_PIPELINE_H

#include <windows.h>
#include <deque>
#include <mutex>
#include <condition_variable>
#include "telemetry.h"

/* ── Thread-safe event queue ──────────────────────────────────────────────── */

class EventQueue {
public:
    /* Push an event into the queue. Thread-safe. */
    void Push(const SENTINEL_EVENT& evt);

    /*
     * Pop an event from the queue. Blocks up to timeoutMs.
     * Returns true if an event was dequeued, false on timeout or shutdown.
     */
    bool Pop(SENTINEL_EVENT& evt, DWORD timeoutMs);

    /* Signal shutdown — wake all waiting consumers. */
    void Shutdown();

    /* Get current queue depth (approximate). */
    size_t Size();

private:
    std::deque<SENTINEL_EVENT>  m_queue;
    std::mutex                  m_mutex;
    std::condition_variable     m_cv;
    bool                        m_shutdown = false;
};

/* ── Pipeline lifecycle ───────────────────────────────────────────────────── */

/*
 * Start all pipeline threads:
 *   - Driver port receiver
 *   - Named pipe server (listener + per-client handlers)
 *   - Event processing thread
 */
void PipelineStart();

/*
 * Stop all pipeline threads with graceful shutdown (5 second timeout).
 * Drains remaining events before exiting.
 */
void PipelineStop();

#endif /* SENTINEL_PIPELINE_H */
