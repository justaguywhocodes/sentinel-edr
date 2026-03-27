/*
 * akesoedr-agent/config.cpp
 * INI config file parser and serializer.
 *
 * P9-T3: Configuration File.
 * P9-T4: Rules Update (git repo URLs).
 */

#include "config.h"

#include <fstream>
#include <string>
#include <unordered_map>
#include <cstdio>
#include <cstring>
#include <algorithm>

/* ── Helpers ────────────────────────────────────────────────────────────── */

static std::string
Trim(const std::string& s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static void
ToLower(std::string& s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
}

/* ── INI parser ─────────────────────────────────────────────────────────── */

/*
 * Parsed INI: section → { key → value }.
 * Section and key names are lowered; values are trimmed but case-preserved.
 */
using IniMap = std::unordered_map<std::string,
                std::unordered_map<std::string, std::string>>;

static IniMap
ParseIniFile(const char* path)
{
    IniMap ini;
    std::ifstream ifs(path);
    if (!ifs.is_open()) return ini;

    std::string currentSection;
    std::string line;

    while (std::getline(ifs, line)) {
        std::string trimmed = Trim(line);

        /* Skip blank lines and comments */
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }

        /* Section header */
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            currentSection = trimmed.substr(1, trimmed.size() - 2);
            ToLower(currentSection);
            continue;
        }

        /* Key = value */
        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) {
            continue;   /* Malformed line — skip silently */
        }

        std::string key   = Trim(trimmed.substr(0, eq));
        std::string value = Trim(trimmed.substr(eq + 1));
        ToLower(key);

        ini[currentSection][key] = value;
    }

    return ini;
}

/* Lookup helper — returns empty string if not found */
static std::string
IniGet(const IniMap& ini, const std::string& section, const std::string& key)
{
    auto sit = ini.find(section);
    if (sit == ini.end()) return {};
    auto kit = sit->second.find(key);
    if (kit == sit->second.end()) return {};
    return kit->second;
}

static UINT32
IniGetUint(const IniMap& ini, const std::string& section,
           const std::string& key, UINT32 fallback)
{
    std::string val = IniGet(ini, section, key);
    if (val.empty()) return fallback;
    try {
        return static_cast<UINT32>(std::stoul(val));
    } catch (...) {
        return fallback;
    }
}

/* ── ConfigSetDefaults ──────────────────────────────────────────────────── */

void
ConfigSetDefaults(AkesoEDRConfig& cfg)
{
    memset(&cfg, 0, sizeof(cfg));

    strcpy_s(cfg.logPath,      "C:\\AkesoEDR\\agent_events.jsonl");
    wcscpy_s(cfg.amsiDllPath,  L"C:\\AkesoEDR\\akesoedr-amsi.dll");
    strcpy_s(cfg.rulesDir,     "C:\\AkesoEDR\\rules");
    strcpy_s(cfg.yaraRulesDir, "C:\\AkesoEDR\\yara-rules");

    cfg.scanMaxFileSize    = 50 * 1024 * 1024;   /* 50 MB */
    cfg.scanMaxRegionSize  = 10 * 1024 * 1024;   /* 10 MB */
    cfg.scanCacheTtlSec    = 300;                 /* 5 minutes */
    cfg.logMaxSizeBytes    = 100 * 1024 * 1024;   /* 100 MB */
    cfg.netMaxEventsPerSec = 100;

    /* [git] — no default repo URLs */
    cfg.rulesRepoUrl[0]     = '\0';
    cfg.yaraRulesRepoUrl[0] = '\0';

    /* [output.siem] — disabled by default */
    cfg.siemEnabled          = false;
    cfg.siemEndpoint[0]      = '\0';
    cfg.siemApiKey[0]        = '\0';
    cfg.siemBatchSize        = 100;
    cfg.siemFlushIntervalSec = 10;
    cfg.siemSpillMaxSizeMb   = 500;

    /* [av] — AkesoAV integration, disabled by default */
    cfg.avEnabled          = false;
    cfg.avDllPath[0]       = '\0';
    cfg.avDbPath[0]        = '\0';
    cfg.avHeuristicLevel   = 2;
    cfg.avScanTimeoutMs    = 5000;
}

/* ── ConfigLoad ─────────────────────────────────────────────────────────── */

bool
ConfigLoad(AkesoEDRConfig& cfg, const char* path)
{
    IniMap ini = ParseIniFile(path);
    if (ini.empty()) {
        /* Could not open the file, or it was entirely empty / comments */
        /* Check if the file actually exists */
        std::ifstream test(path);
        if (!test.is_open()) {
            return false;
        }
        /* File exists but has no active keys — that's fine, defaults remain */
        strcpy_s(cfg.configFilePath, path);
        return true;
    }

    strcpy_s(cfg.configFilePath, path);

    /* [paths] */
    std::string val;

    val = IniGet(ini, "paths", "log_path");
    if (!val.empty()) {
        strcpy_s(cfg.logPath, val.c_str());
    }

    val = IniGet(ini, "paths", "amsi_dll");
    if (!val.empty()) {
        /* Convert narrow → wide for amsiDllPath */
        MultiByteToWideChar(CP_UTF8, 0, val.c_str(), -1,
                            cfg.amsiDllPath, MAX_PATH);
    }

    val = IniGet(ini, "paths", "rules_dir");
    if (!val.empty()) {
        strcpy_s(cfg.rulesDir, val.c_str());
    }

    val = IniGet(ini, "paths", "yara_rules_dir");
    if (!val.empty()) {
        strcpy_s(cfg.yaraRulesDir, val.c_str());
    }

    /* [scanner] — MB values are multiplied */
    UINT32 mb;
    mb = IniGetUint(ini, "scanner", "max_file_size_mb",
                    cfg.scanMaxFileSize / (1024 * 1024));
    cfg.scanMaxFileSize = mb * 1024 * 1024;

    mb = IniGetUint(ini, "scanner", "max_region_size_mb",
                    cfg.scanMaxRegionSize / (1024 * 1024));
    cfg.scanMaxRegionSize = mb * 1024 * 1024;

    cfg.scanCacheTtlSec = IniGetUint(ini, "scanner", "cache_ttl_sec",
                                     cfg.scanCacheTtlSec);

    /* [logging] — MB value */
    mb = IniGetUint(ini, "logging", "max_log_size_mb",
                    cfg.logMaxSizeBytes / (1024 * 1024));
    cfg.logMaxSizeBytes = mb * 1024 * 1024;

    /* [network] */
    cfg.netMaxEventsPerSec = IniGetUint(ini, "network", "max_events_per_sec",
                                        cfg.netMaxEventsPerSec);

    /* [git] */
    val = IniGet(ini, "git", "rules_repo_url");
    if (!val.empty()) {
        strcpy_s(cfg.rulesRepoUrl, val.c_str());
    }

    val = IniGet(ini, "git", "yara_rules_repo_url");
    if (!val.empty()) {
        strcpy_s(cfg.yaraRulesRepoUrl, val.c_str());
    }

    /* [output.siem] */
    val = IniGet(ini, "output.siem", "enabled");
    if (!val.empty()) {
        std::string lower = val;
        ToLower(lower);
        cfg.siemEnabled = (lower == "true" || lower == "1" || lower == "yes");
    }

    val = IniGet(ini, "output.siem", "endpoint");
    if (!val.empty()) {
        strcpy_s(cfg.siemEndpoint, val.c_str());
    }

    val = IniGet(ini, "output.siem", "api_key");
    if (!val.empty()) {
        strcpy_s(cfg.siemApiKey, val.c_str());
    }

    cfg.siemBatchSize = IniGetUint(ini, "output.siem", "batch_size",
                                    cfg.siemBatchSize);

    cfg.siemFlushIntervalSec = IniGetUint(ini, "output.siem",
                                           "flush_interval_sec",
                                           cfg.siemFlushIntervalSec);

    cfg.siemSpillMaxSizeMb = IniGetUint(ini, "output.siem",
                                         "spill_max_size_mb",
                                         cfg.siemSpillMaxSizeMb);

    /* [av] */
    val = IniGet(ini, "av", "enabled");
    if (!val.empty()) {
        std::string lower = val;
        ToLower(lower);
        cfg.avEnabled = (lower == "true" || lower == "1" || lower == "yes");
    }

    val = IniGet(ini, "av", "dll_path");
    if (!val.empty()) {
        strcpy_s(cfg.avDllPath, val.c_str());
    }

    val = IniGet(ini, "av", "db_path");
    if (!val.empty()) {
        strcpy_s(cfg.avDbPath, val.c_str());
    }

    cfg.avHeuristicLevel = IniGetUint(ini, "av", "heuristic_level",
                                       cfg.avHeuristicLevel);
    cfg.avScanTimeoutMs  = IniGetUint(ini, "av", "scan_timeout_ms",
                                       cfg.avScanTimeoutMs);

    return true;
}

/* ── ConfigToJson ───────────────────────────────────────────────────────── */

/* Escape backslashes for JSON string values */
static void
JsonEscape(std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        if (c == '\\')      out += "\\\\";
        else if (c == '"')  out += "\\\"";
        else                out += c;
    }
    s = std::move(out);
}

std::string
ConfigToJson(const AkesoEDRConfig& cfg)
{
    /* Convert wchar paths to narrow for JSON output */
    char amsiNarrow[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, cfg.amsiDllPath, -1,
                        amsiNarrow, MAX_PATH, nullptr, nullptr);

    std::string logPath      = cfg.logPath;
    std::string amsiDll      = amsiNarrow;
    std::string rulesDir     = cfg.rulesDir;
    std::string yaraRulesDir = cfg.yaraRulesDir;
    std::string configFile   = cfg.configFilePath;
    std::string rulesRepo    = cfg.rulesRepoUrl;
    std::string yaraRepo     = cfg.yaraRulesRepoUrl;
    std::string siemEndpoint = cfg.siemEndpoint;
    std::string siemApiKey   = cfg.siemApiKey;
    std::string avDllPath    = cfg.avDllPath;
    std::string avDbPath     = cfg.avDbPath;

    JsonEscape(logPath);
    JsonEscape(amsiDll);
    JsonEscape(rulesDir);
    JsonEscape(yaraRulesDir);
    JsonEscape(configFile);
    JsonEscape(rulesRepo);
    JsonEscape(yaraRepo);
    JsonEscape(siemEndpoint);
    JsonEscape(siemApiKey);
    JsonEscape(avDllPath);
    JsonEscape(avDbPath);

    /* Mask API key for display — show only last 4 chars */
    std::string maskedKey;
    if (siemApiKey.size() > 4) {
        maskedKey = std::string(siemApiKey.size() - 4, '*')
                    + siemApiKey.substr(siemApiKey.size() - 4);
    } else {
        maskedKey = siemApiKey;
    }

    char buf[4096];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{"
        "\"config_file\":\"%s\","
        "\"paths\":{"
            "\"log_path\":\"%s\","
            "\"amsi_dll\":\"%s\","
            "\"rules_dir\":\"%s\","
            "\"yara_rules_dir\":\"%s\""
        "},"
        "\"scanner\":{"
            "\"max_file_size_mb\":%u,"
            "\"max_region_size_mb\":%u,"
            "\"cache_ttl_sec\":%u"
        "},"
        "\"logging\":{"
            "\"max_log_size_mb\":%u"
        "},"
        "\"network\":{"
            "\"max_events_per_sec\":%u"
        "},"
        "\"git\":{"
            "\"rules_repo_url\":\"%s\","
            "\"yara_rules_repo_url\":\"%s\""
        "},"
        "\"output_siem\":{"
            "\"enabled\":%s,"
            "\"endpoint\":\"%s\","
            "\"api_key\":\"%s\","
            "\"batch_size\":%u,"
            "\"flush_interval_sec\":%u,"
            "\"spill_max_size_mb\":%u"
        "},"
        "\"av\":{"
            "\"enabled\":%s,"
            "\"dll_path\":\"%s\","
            "\"db_path\":\"%s\","
            "\"heuristic_level\":%u,"
            "\"scan_timeout_ms\":%u"
        "}"
        "}",
        configFile.c_str(),
        logPath.c_str(),
        amsiDll.c_str(),
        rulesDir.c_str(),
        yaraRulesDir.c_str(),
        cfg.scanMaxFileSize / (1024 * 1024),
        cfg.scanMaxRegionSize / (1024 * 1024),
        cfg.scanCacheTtlSec,
        cfg.logMaxSizeBytes / (1024 * 1024),
        cfg.netMaxEventsPerSec,
        rulesRepo.c_str(),
        yaraRepo.c_str(),
        cfg.siemEnabled ? "true" : "false",
        siemEndpoint.c_str(),
        maskedKey.c_str(),
        cfg.siemBatchSize,
        cfg.siemFlushIntervalSec,
        cfg.siemSpillMaxSizeMb,
        cfg.avEnabled ? "true" : "false",
        avDllPath.c_str(),
        avDbPath.c_str(),
        cfg.avHeuristicLevel,
        cfg.avScanTimeoutMs);

    return buf;
}
