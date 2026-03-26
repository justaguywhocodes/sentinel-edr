/*
 * akesoedr-agent/event_processor.h
 * Event processing orchestrator.
 *
 * Wires together the ProcessTable (enrichment), RuleEngine (detection),
 * and JsonWriter (output) to process each AKESOEDR_EVENT from the
 * pipeline queue.
 *
 * P4-T2: Event Processing & JSON Logging.
 * P4-T3: Single-Event Rule Engine.
 * P4-T4: Sequence Rule Engine.
 * P4-T5: Threshold Rule Engine.
 * P6-T3: Connection Table.
 * P9-T1: CLI command support (alert history, rule reload, on-demand scan).
 * P9-T3: Configuration file support.
 * P9-T4: Rules Update (validate-and-reload).
 */

#ifndef AKESOEDR_EVENT_PROCESSOR_H
#define AKESOEDR_EVENT_PROCESSOR_H

#include <windows.h>
#include <deque>
#include <mutex>
#include <string>
#include "telemetry.h"
#include "config.h"
#include "process_table.h"
#include "network_table.h"
#include "json_writer.h"
#include "rules/rule_engine.h"
#include "rules/sequence_engine.h"
#include "rules/threshold_engine.h"
#include "scanner/yara_scanner.h"
#include "scanner/onaccess_scanner.h"
#include "scanner/memory_scanner.h"
#include "output/siem_writer.h"
#include "crossvalidation.h"

/* ── Rule count summary (returned by GetRuleCounts) ──────────────────────── */

struct RuleCountSummary {
    size_t singleEvent;
    size_t sequence;
    size_t threshold;
    int    yara;
};

/* P9-T4: Result of validate-and-reload operation */
struct RulesUpdateResult {
    bool        validated;
    bool        reloaded;
    int         singleCount;
    int         sequenceCount;
    int         thresholdCount;
    int         yaraCount;
    std::string error;
};

class EventProcessor {
public:
    /*
     * Initialize the event processor with the loaded configuration.
     * Opens the JSON log file, loads detection rules, initializes scanners.
     * Returns false if the log file cannot be opened.
     */
    bool Init(const AkesoEDRConfig& cfg);

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
    void Process(const AKESOEDR_EVENT& evt);

    /* Shut down the processor, flush and close the log file. */
    void Shutdown();

    /* Access the YARA scanner (for on-demand scans, hot-reload from CLI). */
    YaraScanner& GetYaraScanner() { return m_yaraScanner; }

    /* Access the JSON writer (for AMSI integrity alerts, P11-T4). */
    JsonWriter& GetJsonWriter() { return m_jsonWriter; }

    /* Total events processed since Init. */
    ULONGLONG EventsProcessed() const { return m_eventsProcessed; }

    /* Access the connection table (for periodic summary, CLI queries). */
    NetworkTable& GetNetworkTable() { return m_networkTable; }

    /* Access the process table (for CLI inspection commands). */
    ProcessTable& GetProcessTable() { return m_processTable; }

    /* Access the active configuration (for CLI config command). */
    const AkesoEDRConfig& GetConfig() const { return m_config; }

    /* ── P9-T1: CLI command support ─────────────────────────────────────── */

    /*
     * Hot-reload all detection rules (single-event, sequence, threshold).
     * Returns true if all three engines reloaded successfully.
     */
    bool ReloadRules();

    /*
     * P9-T4: Validate rules first (dry-run parse), then reload if valid.
     * Returns detailed result with validation status and rule counts.
     * On failure, old rules remain active.
     */
    RulesUpdateResult ValidateAndReloadRules();

    /* Get counts from all rule engines. */
    RuleCountSummary GetRuleCounts() const;

    /* Whether the YARA scanner is initialized and ready. */
    bool IsYaraReady() const { return m_yaraScanner.IsReady(); }

    /*
     * On-demand file scan via YARA.
     * Returns true if scan completed; populates result.
     */
    bool ScanFileOnDemand(const wchar_t* path,
                          AKESOEDR_SCANNER_EVENT& result);

    /*
     * Get recent alerts (thread-safe copy).
     * Returns up to the last ALERT_HISTORY_MAX alerts.
     */
    std::deque<AKESOEDR_EVENT> GetAlertHistory();

private:
    AkesoEDRConfig    m_config;
    ProcessTable      m_processTable;
    NetworkTable      m_networkTable;
    RuleEngine        m_ruleEngine;
    SequenceEngine    m_sequenceEngine;
    ThresholdEngine   m_thresholdEngine;
    JsonWriter        m_jsonWriter;
    YaraScanner       m_yaraScanner;
    OnAccessScanner   m_onAccessScanner;
    MemoryScanner     m_memoryScanner;
    SiemWriter        m_siemWriter;
    CrossValidator    m_crossValidator;
    ULONGLONG         m_eventsProcessed = 0;

    /* Alert ring buffer for CLI `alerts` command (P9-T1) */
    static constexpr size_t ALERT_HISTORY_MAX = 100;
    std::deque<AKESOEDR_EVENT> m_alertHistory;
    std::mutex                 m_alertMutex;

    void PrintSummary(const AKESOEDR_EVENT& evt);
    void RecordAlert(const AKESOEDR_EVENT& alert);
};

#endif /* AKESOEDR_EVENT_PROCESSOR_H */
