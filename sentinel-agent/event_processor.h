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
 */

#ifndef SENTINEL_EVENT_PROCESSOR_H
#define SENTINEL_EVENT_PROCESSOR_H

#include <windows.h>
#include "telemetry.h"
#include "process_table.h"
#include "network_table.h"
#include "json_writer.h"
#include "rules/rule_engine.h"
#include "rules/sequence_engine.h"
#include "rules/threshold_engine.h"

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

    /* Total events processed since Init. */
    ULONGLONG EventsProcessed() const { return m_eventsProcessed; }

    /* Access the connection table (for periodic summary, CLI queries). */
    NetworkTable& GetNetworkTable() { return m_networkTable; }

private:
    ProcessTable      m_processTable;
    NetworkTable      m_networkTable;
    RuleEngine        m_ruleEngine;
    SequenceEngine    m_sequenceEngine;
    ThresholdEngine   m_thresholdEngine;
    JsonWriter        m_jsonWriter;
    ULONGLONG       m_eventsProcessed = 0;

    void PrintSummary(const SENTINEL_EVENT& evt);
};

#endif /* SENTINEL_EVENT_PROCESSOR_H */
