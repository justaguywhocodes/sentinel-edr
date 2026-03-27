/* edr_shim.h -- AkesoEDR integration shim for akesoav.dll.
 *
 * This header provides the AVEngine wrapper class that loads akesoav.dll
 * at runtime via LoadLibrary/GetProcAddress, dispatches scans from
 * minifilter file events with a 5-second timeout, and merges AV fields
 * into the EDR telemetry struct.
 *
 * Usage:
 *   AVEngine av;
 *   if (av.init("C:\\ProgramData\\Akeso\\akesoedr.conf"))
 *       auto result = av.scan_file("C:\\path\\to\\file.exe");
 *
 * Graceful degradation: if akesoav.dll is missing or fails to load,
 * the shim logs a warning and all scan calls return empty results
 * with av_available() returning false.
 */

#ifndef AKESOAV_EDR_SHIM_H
#define AKESOAV_EDR_SHIM_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <string>

/* Forward-declare opaque engine type from akesoav.h */
struct akav_engine;
typedef struct akav_engine akav_engine_t;

/* ── Function pointer typedefs matching akesoav.h C API ────────── */

/* We need scan_options_t and scan_result_t structures.
 * Rather than including akesoav.h (which would create a build-time
 * dependency on the AV project), we replicate the ABI-compatible
 * structs here. These MUST match akesoav.h exactly. */

typedef int akav_error_t;

enum {
    EDR_AKAV_OK            =  0,
    EDR_AKAV_ERROR         = -1,
    EDR_AKAV_ERROR_TIMEOUT = -6,
};

enum {
    EDR_AKAV_HEUR_OFF    = 0,
    EDR_AKAV_HEUR_LOW    = 1,
    EDR_AKAV_HEUR_MEDIUM = 2,
    EDR_AKAV_HEUR_HIGH   = 3,
};

#define EDR_AKAV_MAX_MALWARE_NAME  256
#define EDR_AKAV_MAX_SIG_ID         64
#define EDR_AKAV_MAX_SCANNER_ID     64
#define EDR_AKAV_MAX_FILE_TYPE      32
#define EDR_AKAV_MAX_WARNINGS        8
#define EDR_AKAV_MAX_WARNING_LEN   128

typedef struct {
    int              scan_archives;
    int              scan_packed;
    int              use_heuristics;
    int              heuristic_level;
    int64_t          max_filesize;
    int              max_scan_depth;
    int              timeout_ms;
    int              scan_memory;
    int              use_cache;
    int              use_whitelist;
} edr_akav_scan_options_t;

typedef struct {
    int              found;
    char             malware_name[EDR_AKAV_MAX_MALWARE_NAME];
    char             signature_id[EDR_AKAV_MAX_SIG_ID];
    char             scanner_id[EDR_AKAV_MAX_SCANNER_ID];
    char             file_type[EDR_AKAV_MAX_FILE_TYPE];
    double           heuristic_score;
    uint32_t         crc1;
    uint32_t         crc2;
    int              in_whitelist;
    int64_t          total_size;
    int64_t          scanned_size;
    int              cached;
    int              scan_time_ms;
    int              warning_count;
    char             warnings[EDR_AKAV_MAX_WARNINGS][EDR_AKAV_MAX_WARNING_LEN];
} edr_akav_scan_result_t;

/* Function pointer types for the C API */
typedef akav_error_t (*pfn_akav_engine_create)(akav_engine_t** engine);
typedef akav_error_t (*pfn_akav_engine_init)(akav_engine_t* engine, const char* config_path);
typedef akav_error_t (*pfn_akav_engine_load_signatures)(akav_engine_t* engine, const char* db_path);
typedef akav_error_t (*pfn_akav_engine_destroy)(akav_engine_t* engine);
typedef akav_error_t (*pfn_akav_scan_file)(akav_engine_t* engine, const char* path,
                                           const edr_akav_scan_options_t* opts,
                                           edr_akav_scan_result_t* result);
typedef akav_error_t (*pfn_akav_scan_buffer)(akav_engine_t* engine,
                                             const uint8_t* buf, size_t len,
                                             const char* name,
                                             const edr_akav_scan_options_t* opts,
                                             edr_akav_scan_result_t* result);
typedef akav_error_t (*pfn_akav_cache_clear)(akav_engine_t* engine);
typedef akav_error_t (*pfn_akav_cache_stats)(akav_engine_t* engine,
                                             uint64_t* hits, uint64_t* misses,
                                             uint64_t* entries);
typedef void         (*pfn_akav_scan_options_default)(edr_akav_scan_options_t* opts);
typedef const char*  (*pfn_akav_engine_version)(void);
typedef const char*  (*pfn_akav_db_version)(akav_engine_t* engine);
typedef const char*  (*pfn_akav_strerror)(akav_error_t err);

/* ── AV telemetry fields for EDR event enrichment ──────────────── */

struct AVTelemetry {
    bool         av_detected;                                  /* true = malware found      */
    char         av_malware_name[EDR_AKAV_MAX_MALWARE_NAME];   /* Detection name            */
    char         av_signature_id[EDR_AKAV_MAX_SIG_ID];         /* Matched signature         */
    char         av_scanner_id[EDR_AKAV_MAX_SCANNER_ID];       /* Engine layer              */
    char         av_file_type[EDR_AKAV_MAX_FILE_TYPE];         /* Detected format           */
    double       av_heuristic_score;                           /* Combined score            */
    bool         av_scan_cached;                               /* Result from cache         */
    int          av_scan_time_ms;                              /* Wall-clock scan time      */
    bool         av_available;                                 /* AV engine loaded          */
    bool         av_timeout;                                   /* Scan timed out            */
    bool         av_in_whitelist;                              /* File is whitelisted       */
};

/* ── AVEngine: runtime wrapper for akesoav.dll ─────────────────── */

class AVEngine {
public:
    AVEngine();
    ~AVEngine();

    /* Non-copyable, non-movable */
    AVEngine(const AVEngine&) = delete;
    AVEngine& operator=(const AVEngine&) = delete;

    /* Initialize: load DLL, resolve symbols, create+init engine.
     * config_path: path to akesoedr.conf (reads [av] section for
     * dll_path, db_path, heuristic_level, scan_timeout_ms).
     * Returns true on success, false on failure (graceful degradation). */
    bool init(const char* config_path);

    /* Shutdown: destroy engine, unload DLL. Safe to call multiple times. */
    void shutdown();

    /* Is the AV engine available? */
    bool av_available() const { return engine_ != nullptr; }

    /* Scan a file with 5-second timeout (configurable).
     * Returns populated AVTelemetry struct.
     * On timeout or error, returns defaults with av_timeout=true. */
    AVTelemetry scan_file(const char* path);

    /* Scan a buffer (e.g., from AMSI). Same timeout behavior. */
    AVTelemetry scan_buffer(const uint8_t* buf, size_t len, const char* name);

    /* Reload signatures from the configured DB path. */
    bool reload_signatures();

    /* Get cache stats */
    bool cache_stats(uint64_t* hits, uint64_t* misses, uint64_t* entries);

    /* Clear cache */
    bool cache_clear();

    /* Get version strings */
    const char* engine_version() const;
    const char* db_version() const;

    /* Config accessors */
    const std::string& dll_path() const { return dll_path_; }
    const std::string& db_path() const { return db_path_; }
    int scan_timeout_ms() const { return scan_timeout_ms_; }

    /* Expose handles for SIEM callback registration */
    void* engine_handle() const { return static_cast<void*>(engine_); }
    HMODULE dll_handle() const { return dll_; }

private:
    /* DLL handle and resolved function pointers */
    HMODULE                           dll_;
    akav_engine_t*                    engine_;

    pfn_akav_engine_create            fn_create_;
    pfn_akav_engine_init              fn_init_;
    pfn_akav_engine_load_signatures   fn_load_sigs_;
    pfn_akav_engine_destroy           fn_destroy_;
    pfn_akav_scan_file                fn_scan_file_;
    pfn_akav_scan_buffer              fn_scan_buffer_;
    pfn_akav_cache_clear              fn_cache_clear_;
    pfn_akav_cache_stats              fn_cache_stats_;
    pfn_akav_scan_options_default     fn_opts_default_;
    pfn_akav_engine_version           fn_version_;
    pfn_akav_db_version               fn_db_version_;
    pfn_akav_strerror                 fn_strerror_;

    /* Config */
    std::string dll_path_;
    std::string db_path_;
    std::string config_path_;
    int         heuristic_level_;
    int         scan_timeout_ms_;

    /* Internal helpers */
    bool load_dll();
    bool resolve_symbols();
    bool parse_config(const char* config_path);

    /* Timeout-wrapped scan: runs the scan on a worker thread,
     * waits up to scan_timeout_ms_. */
    struct ScanWork {
        AVEngine*                 self;
        const char*               path;
        const uint8_t*            buf;
        size_t                    buf_len;
        const char*               name;
        edr_akav_scan_options_t   opts;
        edr_akav_scan_result_t    result;
        akav_error_t              err;
    };

    static DWORD WINAPI scan_thread_proc(LPVOID param);
    AVTelemetry do_scan_with_timeout(ScanWork* work, bool is_file);
    static AVTelemetry make_telemetry(const edr_akav_scan_result_t* result,
                                      bool available, bool timeout);
    static AVTelemetry empty_telemetry(bool available, bool timeout);
};

#endif /* AKESOAV_EDR_SHIM_H */
