/*
 * sentinel-agent/rules/sequence_engine.cpp
 * Multi-step sequence detection engine implementation.
 *
 * P4-T4: Sequence Rule Engine.
 */

#include "sequence_engine.h"
#include "rule_engine.h"
#include "rule_parser.h"
#include "json_writer.h"
#include <cstdio>
#include <algorithm>
#include <objbase.h>

/* ── Init ────────────────────────────────────────────────────────────────── */

bool
SequenceEngine::Init(const std::string& rulesDir)
{
    m_rules.clear();
    m_trackers.clear();

    if (!RuleParser::ParseSequenceDirectory(rulesDir, m_rules)) {
        std::fprintf(stderr, "SequenceEngine: Failed to parse rules dir %s\n",
                     rulesDir.c_str());
        return false;
    }

    /* Remove disabled rules */
    m_rules.erase(
        std::remove_if(m_rules.begin(), m_rules.end(),
                        [](const SequenceRule& r) { return !r.enabled; }),
        m_rules.end());

    /* Allocate one tracker map per rule */
    m_trackers.resize(m_rules.size());

    std::printf("SentinelAgent: Loaded %zu sequence rule(s)\n",
                m_rules.size());

    for (const auto& rule : m_rules) {
        std::printf("  - [SEQ] %s [%s] (%zu step%s, %lums window)\n",
                    rule.name.c_str(),
                    SeverityName(rule.severity),
                    rule.steps.size(),
                    rule.steps.size() == 1 ? "" : "s",
                    rule.timeWindowMs);
    }

    return true;
}

/* ── Evaluate ────────────────────────────────────────────────────────────── */

void
SequenceEngine::Evaluate(const SENTINEL_EVENT& evt,
                          ProcessTable& processTable,
                          std::vector<SENTINEL_EVENT>& alerts)
{
    /* Don't evaluate rule engine's own alert events */
    if (evt.Source == SentinelSourceRuleEngine) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);

    for (size_t ri = 0; ri < m_rules.size(); ++ri) {
        const auto& rule = m_rules[ri];

        /* Check source filter */
        if (!rule.sources.empty()) {
            bool sourceMatch = false;
            for (auto src : rule.sources) {
                if (evt.Source == src) {
                    sourceMatch = true;
                    break;
                }
            }
            if (!sourceMatch) continue;
        }

        /* Clean up expired trackers periodically */
        CleanupExpired(ri, rule.timeWindowMs, evt.Timestamp);

        ULONG pid = evt.ProcessCtx.ProcessId;
        auto& trackerMap = m_trackers[ri];
        auto it = trackerMap.find(pid);

        if (it == trackerMap.end()) {
            /* No active tracker for this PID — check step 0 */
            if (StepMatches(evt, rule.steps[0], processTable)) {
                SequenceTracker tracker = {};
                tracker.currentStep = 1;  /* Step 0 matched, next is 1 */
                tracker.firstEventTime = evt.Timestamp;
                tracker.firstEventId = evt.EventId;

                /* If single-step rule, it completes immediately */
                if (rule.steps.size() == 1) {
                    /* Emit alert */
                    SENTINEL_EVENT alertEvt = {};
                    SentinelEventInit(&alertEvt, SentinelSourceRuleEngine,
                                      rule.severity);
                    alertEvt.ProcessCtx = evt.ProcessCtx;

                    auto& alert = alertEvt.Payload.Alert;
                    strncpy_s(alert.RuleName, sizeof(alert.RuleName),
                              rule.name.c_str(), _TRUNCATE);
                    alert.Severity = rule.severity;
                    alert.TriggerSource = evt.Source;
                    alert.TriggerEventId = evt.EventId;

                    alerts.push_back(alertEvt);
                } else {
                    trackerMap[pid] = tracker;
                }
            }
        } else {
            /* Active tracker exists — check if expired */
            if (IsExpired(it->second, evt.Timestamp, rule.timeWindowMs)) {
                trackerMap.erase(it);

                /* Re-check step 0 with current event */
                if (StepMatches(evt, rule.steps[0], processTable)) {
                    SequenceTracker tracker = {};
                    tracker.currentStep = 1;
                    tracker.firstEventTime = evt.Timestamp;
                    tracker.firstEventId = evt.EventId;
                    trackerMap[pid] = tracker;
                }
                continue;
            }

            /* Check if current event matches the next expected step */
            size_t nextStep = it->second.currentStep;
            if (StepMatches(evt, rule.steps[nextStep], processTable)) {
                it->second.currentStep = nextStep + 1;

                /* Check if sequence is now complete */
                if (it->second.currentStep >= rule.steps.size()) {
                    /* Sequence complete — emit alert */
                    SENTINEL_EVENT alertEvt = {};
                    SentinelEventInit(&alertEvt, SentinelSourceRuleEngine,
                                      rule.severity);
                    alertEvt.ProcessCtx = evt.ProcessCtx;

                    auto& alert = alertEvt.Payload.Alert;
                    strncpy_s(alert.RuleName, sizeof(alert.RuleName),
                              rule.name.c_str(), _TRUNCATE);
                    alert.Severity = rule.severity;
                    alert.TriggerSource = evt.Source;
                    alert.TriggerEventId = it->second.firstEventId;

                    alerts.push_back(alertEvt);

                    /* Reset tracker */
                    trackerMap.erase(it);
                }
            }
            /* If event doesn't match next step, no change (non-strict) */
        }
    }
}

/* ── StepMatches ─────────────────────────────────────────────────────────── */

bool
SequenceEngine::StepMatches(const SENTINEL_EVENT& evt,
                             const SequenceStep& step,
                             ProcessTable& processTable)
{
    /* All conditions in the step must match (AND logic) */
    for (const auto& cond : step.conditions) {
        if (!RuleEngine::EvaluateCondition(evt, cond, processTable)) {
            return false;
        }
    }
    return !step.conditions.empty();
}

/* ── IsExpired ───────────────────────────────────────────────────────────── */

bool
SequenceEngine::IsExpired(const SequenceTracker& tracker,
                           const LARGE_INTEGER& now,
                           DWORD windowMs)
{
    /* LARGE_INTEGER is in 100-nanosecond intervals */
    LONGLONG elapsed = now.QuadPart - tracker.firstEventTime.QuadPart;
    LONGLONG windowTicks = (LONGLONG)windowMs * 10000LL;  /* ms → 100ns */
    return elapsed > windowTicks;
}

/* ── CleanupExpired ──────────────────────────────────────────────────────── */

void
SequenceEngine::CleanupExpired(size_t ruleIndex, DWORD windowMs,
                                const LARGE_INTEGER& now)
{
    auto& trackerMap = m_trackers[ruleIndex];
    for (auto it = trackerMap.begin(); it != trackerMap.end(); ) {
        if (IsExpired(it->second, now, windowMs)) {
            it = trackerMap.erase(it);
        } else {
            ++it;
        }
    }
}
