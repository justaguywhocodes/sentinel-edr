/*
 * sentinel-agent/rules/rule_parser.cpp
 * Simple YAML-subset parser implementation.
 *
 * P4-T3: Single-Event Rule Engine.
 * P4-T4: Sequence Rule Engine.
 */

#include "rule_parser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <windows.h>

/* ── String helpers ──────────────────────────────────────────────────────── */

std::string
RuleParser::Trim(const std::string& s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string
RuleParser::Unquote(const std::string& s)
{
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') ||
         (s.front() == '\'' && s.back() == '\''))) {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

/* ── Enum parsers ────────────────────────────────────────────────────────── */

static std::string
ToLower(const std::string& s)
{
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return result;
}

ConditionOp
RuleParser::ParseOp(const std::string& op)
{
    std::string lower = ToLower(op);
    if (lower == "equals" || lower == "eq" || lower == "==")
        return ConditionOp::Equals;
    if (lower == "contains" || lower == "has")
        return ConditionOp::Contains;
    if (lower == "regex" || lower == "matches")
        return ConditionOp::Regex;
    if (lower == "greater-than" || lower == "gt" || lower == ">")
        return ConditionOp::GreaterThan;
    return ConditionOp::Equals;     /* Default */
}

SENTINEL_SEVERITY
RuleParser::ParseSeverity(const std::string& sev)
{
    std::string lower = ToLower(sev);
    if (lower == "informational" || lower == "info")
        return SentinelSeverityInformational;
    if (lower == "low")
        return SentinelSeverityLow;
    if (lower == "medium" || lower == "med")
        return SentinelSeverityMedium;
    if (lower == "high")
        return SentinelSeverityHigh;
    if (lower == "critical" || lower == "crit")
        return SentinelSeverityCritical;
    return SentinelSeverityMedium;  /* Default */
}

SENTINEL_EVENT_SOURCE
RuleParser::ParseSource(const std::string& src)
{
    std::string lower = ToLower(src);
    if (lower == "driverprocess")   return SentinelSourceDriverProcess;
    if (lower == "driverthread")    return SentinelSourceDriverThread;
    if (lower == "driverobject")    return SentinelSourceDriverObject;
    if (lower == "driverimageload") return SentinelSourceDriverImageLoad;
    if (lower == "driverregistry")  return SentinelSourceDriverRegistry;
    if (lower == "driverminifilter") return SentinelSourceDriverMinifilter;
    if (lower == "drivernetwork")   return SentinelSourceDriverNetwork;
    if (lower == "hookdll")         return SentinelSourceHookDll;
    if (lower == "etw")             return SentinelSourceEtw;
    if (lower == "amsi")            return SentinelSourceAmsi;
    if (lower == "scanner")         return SentinelSourceScanner;
    if (lower == "selfprotect")     return SentinelSourceSelfProtect;
    return SentinelSourceMax;       /* Invalid */
}

RuleAction
RuleParser::ParseAction(const std::string& action)
{
    std::string lower = ToLower(action);
    if (lower == "block") return RuleAction::Block;
    return RuleAction::Log;         /* Default */
}

/* ── Parse a single rule block ───────────────────────────────────────────── */

bool
RuleParser::ParseRule(const std::vector<std::string>& lines, DetectionRule& rule)
{
    rule.severity = SentinelSeverityMedium;
    rule.action = RuleAction::Log;
    rule.enabled = true;

    bool inConditions = false;
    RuleCondition currentCond = {};
    bool hasCond = false;

    for (const auto& rawLine : lines) {
        std::string line = rawLine;

        /* Strip comments */
        size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }

        std::string trimmed = Trim(line);
        if (trimmed.empty()) continue;

        /* Check if this is a condition list item (starts with -) */
        bool isListItem = false;
        size_t leadingSpaces = line.find_first_not_of(" \t");
        if (leadingSpaces != std::string::npos && leadingSpaces >= 2 &&
            line[leadingSpaces] == '-') {
            isListItem = true;
        }

        if (isListItem && inConditions) {
            /* Save previous condition if complete */
            if (hasCond && !currentCond.field.empty()) {
                rule.conditions.push_back(currentCond);
            }
            currentCond = {};
            hasCond = true;

            /* Parse "- field: value" */
            std::string content = Trim(trimmed.substr(1)); /* Skip '-' */
            size_t colonPos = content.find(':');
            if (colonPos != std::string::npos) {
                std::string key = Trim(content.substr(0, colonPos));
                std::string val = Trim(content.substr(colonPos + 1));
                val = Unquote(val);

                if (key == "field") currentCond.field = val;
                else if (key == "op") currentCond.op = ParseOp(val);
                else if (key == "value") currentCond.value = val;
            }
        } else if (leadingSpaces != std::string::npos && leadingSpaces >= 4 &&
                   inConditions && !isListItem) {
            /* Continuation of a condition item (indented key: value) */
            size_t colonPos = trimmed.find(':');
            if (colonPos != std::string::npos) {
                std::string key = Trim(trimmed.substr(0, colonPos));
                std::string val = Trim(trimmed.substr(colonPos + 1));
                val = Unquote(val);

                if (key == "field") currentCond.field = val;
                else if (key == "op") currentCond.op = ParseOp(val);
                else if (key == "value") currentCond.value = val;
            }
        } else {
            /* Top-level key: value */
            if (inConditions && hasCond && !currentCond.field.empty()) {
                rule.conditions.push_back(currentCond);
                currentCond = {};
                hasCond = false;
            }
            inConditions = false;

            size_t colonPos = trimmed.find(':');
            if (colonPos == std::string::npos) continue;

            std::string key = Trim(trimmed.substr(0, colonPos));
            std::string val = Trim(trimmed.substr(colonPos + 1));
            val = Unquote(val);

            if (key == "name") {
                rule.name = val;
            } else if (key == "source") {
                /* May be comma-separated */
                std::stringstream ss(val);
                std::string token;
                while (std::getline(ss, token, ',')) {
                    token = Trim(token);
                    auto src = ParseSource(token);
                    if (src != SentinelSourceMax) {
                        rule.sources.push_back(src);
                    }
                }
            } else if (key == "severity") {
                rule.severity = ParseSeverity(val);
            } else if (key == "action") {
                rule.action = ParseAction(val);
            } else if (key == "enabled") {
                rule.enabled = (ToLower(val) != "false" && val != "0");
            } else if (key == "conditions") {
                inConditions = true;
            }
        }
    }

    /* Save last condition */
    if (hasCond && !currentCond.field.empty()) {
        rule.conditions.push_back(currentCond);
    }

    /* Validate: must have a name and at least one condition */
    return !rule.name.empty() && !rule.conditions.empty();
}

/* ── Check if a block is a sequence rule ─────────────────────────────────── */

bool
RuleParser::IsSequenceBlock(const std::vector<std::string>& lines)
{
    for (const auto& rawLine : lines) {
        std::string line = rawLine;
        size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }
        std::string trimmed = Trim(line);
        if (trimmed.empty()) continue;

        size_t colonPos = trimmed.find(':');
        if (colonPos == std::string::npos) continue;

        std::string key = Trim(trimmed.substr(0, colonPos));
        std::string val = Trim(trimmed.substr(colonPos + 1));
        val = Unquote(val);

        if (key == "type" && ToLower(val) == "sequence") {
            return true;
        }
    }
    return false;
}

/* ── Helper: read a YAML file into blocks separated by --- ───────────────── */

static bool
ReadBlocks(const std::string& path,
           std::vector<std::vector<std::string>>& blocks)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        std::fprintf(stderr, "RuleParser: Cannot open %s\n", path.c_str());
        return false;
    }

    std::vector<std::string> currentBlock;
    std::string line;

    while (std::getline(file, line)) {
        std::string trimmed = line;
        /* Quick trim for separator check */
        size_t s = trimmed.find_first_not_of(" \t\r\n");
        size_t e = trimmed.find_last_not_of(" \t\r\n");
        if (s != std::string::npos) {
            trimmed = trimmed.substr(s, e - s + 1);
        } else {
            trimmed.clear();
        }

        if (trimmed == "---") {
            if (!currentBlock.empty()) {
                blocks.push_back(std::move(currentBlock));
                currentBlock.clear();
            }
            continue;
        }
        currentBlock.push_back(line);
    }

    if (!currentBlock.empty()) {
        blocks.push_back(std::move(currentBlock));
    }
    return true;
}

/* ── Parse a YAML file for single-event rules ────────────────────────────── */

bool
RuleParser::ParseFile(const std::string& path,
                      std::vector<DetectionRule>& rules)
{
    std::vector<std::vector<std::string>> blocks;
    if (!ReadBlocks(path, blocks)) return false;

    for (const auto& block : blocks) {
        if (IsSequenceBlock(block)) continue; /* Skip sequence rules */
        DetectionRule rule;
        if (ParseRule(block, rule)) {
            rules.push_back(std::move(rule));
        }
    }
    return true;
}

/* ── Scan directory helper (shared by single-event and sequence) ──────────── */

typedef bool (*FileParserFn)(const std::string& path, void* ctx);

static bool
ScanDirectory(const std::string& dirPath, FileParserFn fn, void* ctx)
{
    auto scanExt = [&](const char* ext) {
        std::string searchPath = dirPath + "\\" + ext;
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;
        do {
            std::string filePath = dirPath + "\\" + findData.cFileName;
            fn(filePath, ctx);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    };

    scanExt("*.yaml");
    scanExt("*.yml");
    return true;
}

/* ── Parse all single-event rules in a directory ─────────────────────────── */

bool
RuleParser::ParseDirectory(const std::string& dirPath,
                           std::vector<DetectionRule>& rules)
{
    return ScanDirectory(dirPath,
        [](const std::string& path, void* ctx) -> bool {
            auto* r = static_cast<std::vector<DetectionRule>*>(ctx);
            RuleParser::ParseFile(path, *r);
            return true;
        }, &rules);
}

/* ── Parse a sequence rule block ─────────────────────────────────────────── */

bool
RuleParser::ParseSequenceRule(const std::vector<std::string>& lines,
                               SequenceRule& rule)
{
    rule.severity = SentinelSeverityMedium;
    rule.action = RuleAction::Log;
    rule.enabled = true;
    rule.timeWindowMs = 5000;  /* Default 5s */

    /*
     * Sequence YAML structure:
     *   type: sequence
     *   name: ...
     *   steps:
     *     - conditions:
     *       - field: ...
     *         op: ...
     *         value: ...
     *     - conditions:
     *       - field: ...
     *         ...
     *
     * Parser states:
     *   0 = top-level
     *   1 = inside steps: list
     *   2 = inside a step's conditions: list
     */
    int state = 0;
    SequenceStep currentStep;
    RuleCondition currentCond = {};
    bool hasCond = false;
    bool hasStep = false;

    for (const auto& rawLine : lines) {
        std::string line = rawLine;

        /* Strip comments */
        size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }

        std::string trimmed = Trim(line);
        if (trimmed.empty()) continue;

        size_t indent = line.find_first_not_of(" \t");
        if (indent == std::string::npos) continue;

        bool isDash = (line[indent] == '-');

        if (state == 0) {
            /* Top-level key: value */
            size_t colonPos = trimmed.find(':');
            if (colonPos == std::string::npos) continue;

            std::string key = Trim(trimmed.substr(0, colonPos));
            std::string val = Trim(trimmed.substr(colonPos + 1));
            val = Unquote(val);

            if (key == "name") {
                rule.name = val;
            } else if (key == "type") {
                /* Already validated by IsSequenceBlock */
            } else if (key == "source") {
                std::stringstream ss(val);
                std::string token;
                while (std::getline(ss, token, ',')) {
                    token = Trim(token);
                    auto src = ParseSource(token);
                    if (src != SentinelSourceMax) {
                        rule.sources.push_back(src);
                    }
                }
            } else if (key == "severity") {
                rule.severity = ParseSeverity(val);
            } else if (key == "action") {
                rule.action = ParseAction(val);
            } else if (key == "enabled") {
                rule.enabled = (ToLower(val) != "false" && val != "0");
            } else if (key == "time_window") {
                try { rule.timeWindowMs = std::stoul(val); } catch (...) {}
            } else if (key == "steps") {
                state = 1;
            }
        } else if (state == 1) {
            /* Inside steps: list */
            if (isDash && indent >= 2) {
                /* New step item: "  - conditions:" */
                /* Save previous step if it has conditions */
                if (hasStep) {
                    if (hasCond && !currentCond.field.empty()) {
                        currentStep.conditions.push_back(currentCond);
                        currentCond = {};
                        hasCond = false;
                    }
                    if (!currentStep.conditions.empty()) {
                        rule.steps.push_back(std::move(currentStep));
                    }
                    currentStep = {};
                }
                hasStep = true;

                /* Check if this dash line has "conditions:" */
                std::string after = Trim(trimmed.substr(1));
                if (after == "conditions:" ||
                    ToLower(after).find("conditions") == 0) {
                    state = 2;
                }
            } else if (indent < 2) {
                /* Back to top-level */
                if (hasStep) {
                    if (hasCond && !currentCond.field.empty()) {
                        currentStep.conditions.push_back(currentCond);
                        currentCond = {};
                        hasCond = false;
                    }
                    if (!currentStep.conditions.empty()) {
                        rule.steps.push_back(std::move(currentStep));
                    }
                    currentStep = {};
                    hasStep = false;
                }
                state = 0;

                /* Re-parse this line as top-level */
                size_t colonPos = trimmed.find(':');
                if (colonPos != std::string::npos) {
                    std::string key = Trim(trimmed.substr(0, colonPos));
                    std::string val = Trim(trimmed.substr(colonPos + 1));
                    val = Unquote(val);
                    if (key == "name") rule.name = val;
                    else if (key == "severity") rule.severity = ParseSeverity(val);
                    else if (key == "action") rule.action = ParseAction(val);
                    else if (key == "time_window") {
                        try { rule.timeWindowMs = std::stoul(val); } catch (...) {}
                    }
                }
            }
        } else if (state == 2) {
            /* Inside a step's conditions list */
            if (isDash && indent >= 4) {
                /* New condition: "    - field: ..." */
                if (hasCond && !currentCond.field.empty()) {
                    currentStep.conditions.push_back(currentCond);
                }
                currentCond = {};
                hasCond = true;

                std::string content = Trim(trimmed.substr(1));
                size_t colonPos = content.find(':');
                if (colonPos != std::string::npos) {
                    std::string key = Trim(content.substr(0, colonPos));
                    std::string val = Trim(content.substr(colonPos + 1));
                    val = Unquote(val);
                    if (key == "field") currentCond.field = val;
                    else if (key == "op") currentCond.op = ParseOp(val);
                    else if (key == "value") currentCond.value = val;
                }
            } else if (!isDash && indent >= 6) {
                /* Continuation of condition: "      op: equals" */
                size_t colonPos = trimmed.find(':');
                if (colonPos != std::string::npos) {
                    std::string key = Trim(trimmed.substr(0, colonPos));
                    std::string val = Trim(trimmed.substr(colonPos + 1));
                    val = Unquote(val);
                    if (key == "field") currentCond.field = val;
                    else if (key == "op") currentCond.op = ParseOp(val);
                    else if (key == "value") currentCond.value = val;
                }
            } else if (isDash && indent >= 2 && indent < 4) {
                /* New step item at indent 2: "  - conditions:" */
                /* Save current condition and step */
                if (hasCond && !currentCond.field.empty()) {
                    currentStep.conditions.push_back(currentCond);
                    currentCond = {};
                    hasCond = false;
                }
                if (!currentStep.conditions.empty()) {
                    rule.steps.push_back(std::move(currentStep));
                }
                currentStep = {};

                std::string after = Trim(trimmed.substr(1));
                if (after == "conditions:" ||
                    ToLower(after).find("conditions") == 0) {
                    state = 2; /* Stay in conditions */
                } else {
                    state = 1;
                }
            } else if (indent < 4 && !isDash) {
                /* Leaving conditions — might be "conditions:" for same step
                   or back to steps/top-level */
                if (hasCond && !currentCond.field.empty()) {
                    currentStep.conditions.push_back(currentCond);
                    currentCond = {};
                    hasCond = false;
                }

                if (indent >= 2) {
                    /* Could be indented key within step like "conditions:" */
                    std::string key = Trim(trimmed);
                    if (key == "conditions:") {
                        /* Another conditions block for same step — stay */
                    } else {
                        state = 1;
                    }
                } else {
                    /* Back to top level */
                    if (!currentStep.conditions.empty()) {
                        rule.steps.push_back(std::move(currentStep));
                    }
                    currentStep = {};
                    hasStep = false;
                    state = 0;
                }
            }
        }
    }

    /* Flush remaining state */
    if (hasCond && !currentCond.field.empty()) {
        currentStep.conditions.push_back(currentCond);
    }
    if (hasStep && !currentStep.conditions.empty()) {
        rule.steps.push_back(std::move(currentStep));
    }

    /* Validate: must have a name and at least two steps */
    return !rule.name.empty() && rule.steps.size() >= 2;
}

/* ── Parse sequence rules from a single file ─────────────────────────────── */

bool
RuleParser::ParseSequenceFile(const std::string& path,
                               std::vector<SequenceRule>& rules)
{
    std::vector<std::vector<std::string>> blocks;
    if (!ReadBlocks(path, blocks)) return false;

    for (const auto& block : blocks) {
        if (!IsSequenceBlock(block)) continue; /* Skip single-event rules */
        SequenceRule rule;
        if (ParseSequenceRule(block, rule)) {
            rules.push_back(std::move(rule));
        }
    }
    return true;
}

/* ── Parse all sequence rules in a directory ──────────────────────────────── */

bool
RuleParser::ParseSequenceDirectory(const std::string& dirPath,
                                    std::vector<SequenceRule>& rules)
{
    return ScanDirectory(dirPath,
        [](const std::string& path, void* ctx) -> bool {
            auto* r = static_cast<std::vector<SequenceRule>*>(ctx);
            RuleParser::ParseSequenceFile(path, *r);
            return true;
        }, &rules);
}
