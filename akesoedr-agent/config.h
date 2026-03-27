/*
 * akesoedr-agent/config.h
 * Agent configuration: struct, loader, serializer.
 *
 * All tuneable agent settings live in a single AkesoEDRConfig struct.
 * At startup the agent calls ConfigSetDefaults() then ConfigLoad() to
 * overlay values from an INI-style file (akesoedr.conf).
 *
 * P9-T3: Configuration File.
 * P9-T4: Rules Update (git repo URLs).
 */

#ifndef AKESOEDR_CONFIG_H
#define AKESOEDR_CONFIG_H

#include <windows.h>
#include <string>

/* ── Configuration struct ───────────────────────────────────────────────── */

struct AkesoEDRConfig {
    /* [paths] */
    char        logPath[MAX_PATH];
    wchar_t     amsiDllPath[MAX_PATH];
    char        rulesDir[MAX_PATH];
    char        yaraRulesDir[MAX_PATH];

    /* [scanner] */
    UINT32      scanMaxFileSize;        /* bytes */
    UINT32      scanMaxRegionSize;      /* bytes */
    UINT32      scanCacheTtlSec;

    /* [logging] */
    UINT32      logMaxSizeBytes;

    /* [network] */
    UINT32      netMaxEventsPerSec;

    /* [git] — rule repository URLs for `rules update --init` */
    char        rulesRepoUrl[512];
    char        yaraRulesRepoUrl[512];

    /* [output.siem] — SIEM integration (P9-T5) */
    bool        siemEnabled;
    char        siemEndpoint[512];
    char        siemApiKey[256];
    UINT32      siemBatchSize;
    UINT32      siemFlushIntervalSec;
    UINT32      siemSpillMaxSizeMb;

    /* [av] — AkesoAV integration */
    bool        avEnabled;
    char        avDllPath[MAX_PATH];
    char        avDbPath[MAX_PATH];
    UINT32      avHeuristicLevel;
    UINT32      avScanTimeoutMs;

    /* Meta — which file was loaded (empty string if defaults) */
    char        configFilePath[MAX_PATH];
};

/* ── Functions ──────────────────────────────────────────────────────────── */

/*
 * Fill cfg with compiled-in defaults (matching the values that were
 * previously hardcoded throughout the agent).
 */
void ConfigSetDefaults(AkesoEDRConfig& cfg);

/*
 * Parse an INI-style config file and overlay any present keys onto cfg.
 * Call ConfigSetDefaults() first so missing keys keep their defaults.
 * Returns true if the file was found and parsed (even if empty).
 * Returns false if the file could not be opened (defaults remain).
 */
bool ConfigLoad(AkesoEDRConfig& cfg, const char* path);

/*
 * Serialize the active configuration to a JSON string.
 * Used by the command handler to reply to `akesoedr-cli config`.
 */
std::string ConfigToJson(const AkesoEDRConfig& cfg);

#endif /* AKESOEDR_CONFIG_H */
