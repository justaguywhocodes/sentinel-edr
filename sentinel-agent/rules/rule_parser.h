/*
 * sentinel-agent/rules/rule_parser.h
 * Simple YAML-subset parser for detection rule files.
 *
 * Handles the flat key-value + conditions list structure used by rule
 * files. No external YAML library — just line-by-line parsing.
 *
 * P4-T3: Single-Event Rule Engine.
 * P4-T4: Sequence Rule Engine.
 */

#ifndef SENTINEL_RULE_PARSER_H
#define SENTINEL_RULE_PARSER_H

#include <string>
#include <vector>
#include "rule_types.h"

class RuleParser {
public:
    /* Parse a single .yaml file for single-event rules. */
    static bool ParseFile(const std::string& path,
                          std::vector<DetectionRule>& rules);

    /* Parse all .yaml files in a directory for single-event rules. */
    static bool ParseDirectory(const std::string& dirPath,
                               std::vector<DetectionRule>& rules);

    /* Parse sequence rules from a single .yaml file. */
    static bool ParseSequenceFile(const std::string& path,
                                  std::vector<SequenceRule>& rules);

    /* Parse all sequence rules from .yaml files in a directory. */
    static bool ParseSequenceDirectory(const std::string& dirPath,
                                       std::vector<SequenceRule>& rules);

private:
    static bool ParseRule(const std::vector<std::string>& lines,
                          DetectionRule& rule);

    static bool ParseSequenceRule(const std::vector<std::string>& lines,
                                  SequenceRule& rule);

    /* Check if a block has type: sequence. */
    static bool IsSequenceBlock(const std::vector<std::string>& lines);

    static ConditionOp         ParseOp(const std::string& op);
    static SENTINEL_SEVERITY   ParseSeverity(const std::string& sev);
    static SENTINEL_EVENT_SOURCE ParseSource(const std::string& src);
    static RuleAction          ParseAction(const std::string& action);

    /* Trim whitespace from both ends of a string. */
    static std::string Trim(const std::string& s);

    /* Strip surrounding quotes if present. */
    static std::string Unquote(const std::string& s);
};

#endif /* SENTINEL_RULE_PARSER_H */
