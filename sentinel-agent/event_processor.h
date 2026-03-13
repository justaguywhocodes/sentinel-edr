/*
 * sentinel-agent/event_processor.h
 * Event processing orchestrator.
 *
 * Wires together the ProcessTable (enrichment), RuleEngine (detection),
 * and JsonWriter (output) to process each SENTINEL_EVENT from the
 * pipeline queue.
 *
 * P4-T2: Event Processing & JSON Logging.
 * P4-T3: Single-Event Rule Engine.
 * P4-T4: Sequence Rule Engine.
 * P4-T5: Threshold Rule Engine.
 * P6-T3: Connection Table.
 * P9-T1: CLI command support (alert history, rule reload, on-demand scan).
 */

#ifndef SENTINEL_EVENT_PROCESSOR_H
#define SENTINEL_EVENT_PROCESSOR_H

#include <windows.h>
#include <deque>
#include <mutex>
#include <string>
#include "telemetry.h"
#include "process_table.h"
#include "network_table.h"
#include "json_writer.h"
#include "rules/rule_engine.h"
#include "rules/sequence_engine.h"
#include "rules/threshold_engine.h"
#include "scanner/yara_scanner.h"
#include "scanner/onaccess_scanner.h"
#include "scanner/memory_scanner.h"

/* ── Rule count summary (returned by GetRuleCounts) ──────────────────────── */

struct RuleCountSummary {
    size_t singleEvent;
    size_t sequence;
    size_t threshold;
    int    yara;
};

class EventProcessor {
public:
    /*
     * Initialize the event processor.
     * Opens the JSON log file at the given path.
     * Returns false if the log file cannot be opened.
     */
    bool Init(const char* logPath);

    /*
     * Process a single event:
     *   1. Update process table
     *   2. Evaluate single-event detection rules → emit alerts
     *   3. Evaluate sequence detection rules → emit alerts
     *   4. Evaluate threshold detection rules → emit alerts
     *   5. Enrich with parent image path
     *   6. Write JSON to log file
     *   7. Print summary to stdout (console mode)
     */
    void Process(const SENTINEL_EVENT& evt);

    /* Shut down the processor, flush and close the log file. */
    void Shutdown();

    /* Access the YARA scanner (for on-demand scans, hot-reload from CLI). */
    YaraScanner& GetYaraScanner() { return m_yaraScanner; }

    /* Total events processed since Init. */
    ULONGLONG EventsProcessed() const { return m_eventsProcessed; }

    /* Access the connection table (for periodic summary, CLI queries). */
    NetworkTable& GetNetworkTable() { return m_networkTable; }

    /* ── P9-T1: CLI command support ─────────────────────────────────────── */

    /*
     * Hot-reload all detection rules (single-event, sequence, threshold).
     * Returns true if all three engines reloaded successfully.
     */
    bool ReloadRules();

    /* Get counts from all rule engines. */
    RuleCountSummary GetRuleCounts() const;

    /* Whether the YARA scanner is initialized and ready. */
    bool IsYaraReady() const { return m_yaraScanner.IsReady(); }

    /*
     * On-demand file scan via YARA.
     * Returns true if scan completed; populates result.
     */
    bool ScanFileOnDemand(const wchar_t* path,
                          SENTINEL_SCANNER_EVENT& result);

    /*
     * Get recent alerts (thread-safe copy).
     * Returns up to the last ALERT_HISTORY_MAX alerts.
     */
    std::deque<SENTINEL_EVENT> GetAlertHistory();

private:
    ProcessTable      m_processTable;
    NetworkTable      m_networkTable;
    RuleEngine        m_ruleEngine;
    SequenceEngine    m_sequenceEngine;
    ThresholdEngine   m_thresholdEngine;
    JsonWriter        m_jsonWriter;
    YaraScanner       m_yaraScanner;
    OnAccessScanner   m_onAccessScanner;
    MemoryScanner     m_memoryScanner;
    ULONGLONG         m_eventsProcessed = 0;

    /* Alert ring buffer for CLI `alerts` command (P9-T1) */
    static constexpr size_t ALERT_HISTORY_MAX = 100;
    std::deque<SENTINEL_EVENT> m_alertHistory;
    std::mutex                 m_alertMutex;

    void PrintSummary(const SENTINEL_EVENT& evt);
    void RecordAlert(const SENTINEL_EVENT& alert);
};

#endif /* SENTINEL_EVENT_PROCESSOR_H */
