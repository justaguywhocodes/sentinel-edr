/*
 * sentinel-agent/rules/rule_engine.h
 * Single-event detection rule engine.
 *
 * Evaluates each incoming SENTINEL_EVENT against all loaded detection
 * rules. When all conditions of a rule match, emits a SENTINEL_ALERT_EVENT.
 *
 * P4-T3: Single-Event Rule Engine.
 */

#ifndef SENTINEL_RULE_ENGINE_H
#define SENTINEL_RULE_ENGINE_H

#include <string>
#include <vector>
#include "rule_types.h"
#include "process_table.h"

class RuleEngine {
public:
    /*
     * Load all rules from .yaml files in the given directory.
     * Returns true even if no rules found (empty engine is valid).
     */
    bool Init(const std::string& rulesDir);

    /*
     * Evaluate an event against all loaded rules.
     * For each matching rule, an alert SENTINEL_EVENT is appended to alerts.
     */
    void Evaluate(const SENTINEL_EVENT& evt,
                  ProcessTable& processTable,
                  std::vector<SENTINEL_EVENT>& alerts);

    /* Number of loaded rules. */
    size_t RuleCount() const { return m_rules.size(); }

    /*
     * Evaluate a single condition against an event.
     * Public static so SequenceEngine can reuse it.
     */
    static bool EvaluateCondition(const SENTINEL_EVENT& evt,
                                  const RuleCondition& cond,
                                  ProcessTable& processTable);

    /*
     * Resolve a dot-notation field path to a string value.
     * e.g., "process.imagePath" → "C:\\Windows\\notepad.exe"
     * Public static so SequenceEngine can reuse it.
     */
    static std::string ResolveField(const SENTINEL_EVENT& evt,
                                    const std::string& field,
                                    ProcessTable& processTable);

private:
    std::vector<DetectionRule> m_rules;

    bool MatchesRule(const SENTINEL_EVENT& evt,
                     const DetectionRule& rule,
                     ProcessTable& processTable);
};

#endif /* SENTINEL_RULE_ENGINE_H */
