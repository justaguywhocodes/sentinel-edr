/*
 * sentinel-agent/scanner/onaccess_scanner.h
 * On-access file scanning triggered by minifilter events.
 *
 * When the minifilter driver reports a file CREATE or WRITE, this module
 * invokes the YARA scanner against the file path. A hash-based cache
 * prevents redundant rescans of unchanged content.
 *
 * Thread safety:
 *   OnFileEvent() is only called from the single ProcessorThread,
 *   so the internal cache requires no synchronization.
 *
 * P8-T2: On-Access File Scanning.
 * Book reference: Chapter 9 — Scanners.
 */

#ifndef SENTINEL_ONACCESS_SCANNER_H
#define SENTINEL_ONACCESS_SCANNER_H

#include <windows.h>
#include <string>
#include <unordered_map>
#include <chrono>
#include "telemetry.h"

/* Forward declaration — avoids pulling in yara.h transitively */
class YaraScanner;

class OnAccessScanner {
public:
    /*
     * Bind to a YaraScanner instance (owned by EventProcessor).
     * Must be called after YaraScanner::Init().
     */
    void Init(YaraScanner* scanner);

    /* Release resources (clears cache). */
    void Shutdown();

    /*
     * Evaluate a minifilter file event for on-access scanning.
     *
     * Filters for CREATE / WRITE operations, checks the scan cache,
     * and invokes YaraScanner::ScanFile() on cache miss. If YARA
     * matches, populates alertOut as a SentinelSourceScanner event
     * and returns true. Otherwise returns false.
     */
    bool OnFileEvent(const SENTINEL_FILE_EVENT& fileEvt,
                     SENTINEL_EVENT& alertOut);

private:
    YaraScanner* m_scanner = nullptr;

    /* ── Scan result cache ──────────────────────────────────────────── */

    struct CacheEntry {
        bool    isMatch;
        char    yaraRule[SENTINEL_MAX_YARA_MATCH];
        std::chrono::steady_clock::time_point timestamp;
    };

    std::unordered_map<std::string, CacheEntry> m_cache;

    bool IsCacheValid(const std::string& hash) const;
    void UpdateCache(const std::string& hash, bool isMatch, const char* rule);
};

#endif /* SENTINEL_ONACCESS_SCANNER_H */
