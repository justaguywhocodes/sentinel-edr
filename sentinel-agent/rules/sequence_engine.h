/*
 * sentinel-agent/rules/sequence_engine.h
 * Multi-step sequence detection engine.
 *
 * Tracks ordered event patterns per PID within time windows.
 * Each SequenceRule defines a series of steps; the engine maintains
 * per-PID per-rule state machines that advance through the steps.
 *
 * P4-T4: Sequence Rule Engine.
 */

#ifndef SENTINEL_SEQUENCE_ENGINE_H
#define SENTINEL_SEQUENCE_ENGINE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "rule_types.h"
#include "process_table.h"

/* ── Per-PID state for one sequence rule ────────────────────────────────── */

struct SequenceTracker {
    size_t          currentStep;    /* Next step index to match */
    LARGE_INTEGER   firstEventTime; /* Timestamp when step 0 matched */
    GUID            firstEventId;   /* EventId of the step 0 event */
};

/* ── Sequence engine ────────────────────────────────────────────────────── */

class SequenceEngine {
public:
    /*
     * Load all sequence rules from .yaml files in the given directory.
     * Returns true even if no sequence rules found.
     */
    bool Init(const std::string& rulesDir);

    /*
     * Evaluate an event against all loaded sequence rules.
     * If a sequence completes, an alert SENTINEL_EVENT is appended.
     */
    void Evaluate(const SENTINEL_EVENT& evt,
                  ProcessTable& processTable,
                  std::vector<SENTINEL_EVENT>& alerts);

    /* Number of loaded sequence rules. */
    size_t RuleCount() const { return m_rules.size(); }

private:
    std::vector<SequenceRule> m_rules;

    /* Per-rule, per-PID trackers: m_trackers[ruleIndex][pid] */
    std::vector<std::unordered_map<ULONG, SequenceTracker>> m_trackers;
    std::mutex m_mutex;

    /* Check if all conditions in a step match the event. */
    bool StepMatches(const SENTINEL_EVENT& evt,
                     const SequenceStep& step,
                     ProcessTable& processTable);

    /* Check if a tracker has exceeded the time window. */
    bool IsExpired(const SequenceTracker& tracker,
                   const LARGE_INTEGER& now,
                   DWORD windowMs);

    /* Remove expired trackers for a given rule. */
    void CleanupExpired(size_t ruleIndex, DWORD windowMs,
                        const LARGE_INTEGER& now);
};

#endif /* SENTINEL_SEQUENCE_ENGINE_H */
