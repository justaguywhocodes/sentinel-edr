/* edr_shim.cpp -- AkesoEDR integration shim implementation.
 *
 * Loads akesoav.dll at runtime, resolves all C API symbols via
 * GetProcAddress, and provides the AVEngine wrapper class with
 * timeout-guarded scan dispatch.
 *
 * Config file format (akesoedr.conf, INI-style):
 *   [av]
 *   dll_path = C:\Program Files\Akeso\akesoav.dll
 *   db_path = C:\ProgramData\Akeso\signatures.akavdb
 *   heuristic_level = 2
 *   scan_timeout_ms = 5000
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "edr_shim.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

/* ── Logging helper ────────────────────────────────────────────── */

static void shim_log(const char* level, const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[edr_shim][%s] ", level);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ── AVEngine ──────────────────────────────────────────────────── */

AVEngine::AVEngine()
    : dll_(NULL)
    , engine_(nullptr)
    , fn_create_(nullptr)
    , fn_init_(nullptr)
    , fn_load_sigs_(nullptr)
    , fn_destroy_(nullptr)
    , fn_scan_file_(nullptr)
    , fn_scan_buffer_(nullptr)
    , fn_cache_clear_(nullptr)
    , fn_cache_stats_(nullptr)
    , fn_opts_default_(nullptr)
    , fn_version_(nullptr)
    , fn_db_version_(nullptr)
    , fn_strerror_(nullptr)
    , heuristic_level_(EDR_AKAV_HEUR_MEDIUM)
    , scan_timeout_ms_(5000)
{
}

AVEngine::~AVEngine()
{
    shutdown();
}

/* ── Config parsing ────────────────────────────────────────────── */

/* Simple INI parser: reads [av] section for our keys.
 * Supports:
 *   dll_path = value
 *   db_path = value
 *   heuristic_level = 0-3
 *   scan_timeout_ms = integer
 */
bool AVEngine::parse_config(const char* config_path)
{
    if (!config_path || !config_path[0]) {
        shim_log("warn", "No config path provided, using defaults");
        return true;  /* Not an error — use defaults */
    }

    FILE* f = nullptr;
    if (fopen_s(&f, config_path, "r") != 0 || !f) {
        shim_log("warn", "Cannot open config '%s', using defaults", config_path);
        return true;  /* Not fatal */
    }

    config_path_ = config_path;
    bool in_av_section = false;
    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        /* Strip leading whitespace */
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;

        /* Skip empty lines and comments */
        if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#' || *p == ';')
            continue;

        /* Section header */
        if (*p == '[') {
            in_av_section = (_strnicmp(p, "[av]", 4) == 0);
            continue;
        }

        if (!in_av_section)
            continue;

        /* Key = value */
        char* eq = strchr(p, '=');
        if (!eq) continue;

        /* Extract key (trim trailing whitespace) */
        char* key_end = eq - 1;
        while (key_end > p && (*key_end == ' ' || *key_end == '\t'))
            key_end--;
        *(key_end + 1) = '\0';

        /* Extract value (trim leading whitespace and trailing newline) */
        char* val = eq + 1;
        while (*val == ' ' || *val == '\t') val++;
        size_t vlen = strlen(val);
        while (vlen > 0 && (val[vlen - 1] == '\n' || val[vlen - 1] == '\r' ||
                            val[vlen - 1] == ' ' || val[vlen - 1] == '\t'))
            val[--vlen] = '\0';

        if (_stricmp(p, "dll_path") == 0) {
            dll_path_ = val;
        } else if (_stricmp(p, "db_path") == 0) {
            db_path_ = val;
        } else if (_stricmp(p, "heuristic_level") == 0) {
            heuristic_level_ = atoi(val);
            if (heuristic_level_ < 0 || heuristic_level_ > 3)
                heuristic_level_ = EDR_AKAV_HEUR_MEDIUM;
        } else if (_stricmp(p, "scan_timeout_ms") == 0) {
            scan_timeout_ms_ = atoi(val);
            if (scan_timeout_ms_ < 100)
                scan_timeout_ms_ = 5000;
        }
    }

    fclose(f);
    return true;
}

/* ── DLL loading ───────────────────────────────────────────────── */

bool AVEngine::load_dll()
{
    /* Default DLL path if not configured */
    if (dll_path_.empty()) {
        /* Look next to the agent executable */
        char exe_path[MAX_PATH];
        GetModuleFileNameA(NULL, exe_path, MAX_PATH);
        std::string dir(exe_path);
        auto pos = dir.rfind('\\');
        if (pos != std::string::npos)
            dir = dir.substr(0, pos);
        dll_path_ = dir + "\\akesoav.dll";
    }

    dll_ = LoadLibraryA(dll_path_.c_str());
    if (!dll_) {
        DWORD err = GetLastError();
        shim_log("warn", "LoadLibrary('%s') failed: %lu — AV scanning disabled",
                 dll_path_.c_str(), err);
        return false;
    }

    shim_log("info", "Loaded akesoav.dll from '%s'", dll_path_.c_str());
    return true;
}

/* ── Symbol resolution ─────────────────────────────────────────── */

#define RESOLVE_SYM(name, type) do {                                 \
    fn_##name##_ = (type)GetProcAddress(dll_, "akav_" #name);        \
    if (!fn_##name##_) {                                             \
        shim_log("error", "GetProcAddress('akav_%s') failed", #name);\
        return false;                                                \
    }                                                                \
} while (0)

bool AVEngine::resolve_symbols()
{
    /* These names must match the exported C API exactly */
    fn_create_ = (pfn_akav_engine_create)GetProcAddress(dll_, "akav_engine_create");
    if (!fn_create_) {
        shim_log("error", "GetProcAddress('akav_engine_create') failed");
        return false;
    }

    fn_init_ = (pfn_akav_engine_init)GetProcAddress(dll_, "akav_engine_init");
    if (!fn_init_) {
        shim_log("error", "GetProcAddress('akav_engine_init') failed");
        return false;
    }

    fn_load_sigs_ = (pfn_akav_engine_load_signatures)GetProcAddress(dll_, "akav_engine_load_signatures");
    if (!fn_load_sigs_) {
        shim_log("error", "GetProcAddress('akav_engine_load_signatures') failed");
        return false;
    }

    fn_destroy_ = (pfn_akav_engine_destroy)GetProcAddress(dll_, "akav_engine_destroy");
    if (!fn_destroy_) {
        shim_log("error", "GetProcAddress('akav_engine_destroy') failed");
        return false;
    }

    fn_scan_file_ = (pfn_akav_scan_file)GetProcAddress(dll_, "akav_scan_file");
    if (!fn_scan_file_) {
        shim_log("error", "GetProcAddress('akav_scan_file') failed");
        return false;
    }

    fn_scan_buffer_ = (pfn_akav_scan_buffer)GetProcAddress(dll_, "akav_scan_buffer");
    if (!fn_scan_buffer_) {
        shim_log("error", "GetProcAddress('akav_scan_buffer') failed");
        return false;
    }

    fn_cache_clear_ = (pfn_akav_cache_clear)GetProcAddress(dll_, "akav_cache_clear");
    if (!fn_cache_clear_) {
        shim_log("error", "GetProcAddress('akav_cache_clear') failed");
        return false;
    }

    fn_cache_stats_ = (pfn_akav_cache_stats)GetProcAddress(dll_, "akav_cache_stats");
    if (!fn_cache_stats_) {
        shim_log("error", "GetProcAddress('akav_cache_stats') failed");
        return false;
    }

    fn_opts_default_ = (pfn_akav_scan_options_default)GetProcAddress(dll_, "akav_scan_options_default");
    if (!fn_opts_default_) {
        shim_log("error", "GetProcAddress('akav_scan_options_default') failed");
        return false;
    }

    fn_version_ = (pfn_akav_engine_version)GetProcAddress(dll_, "akav_engine_version");
    if (!fn_version_) {
        shim_log("error", "GetProcAddress('akav_engine_version') failed");
        return false;
    }

    fn_db_version_ = (pfn_akav_db_version)GetProcAddress(dll_, "akav_db_version");
    if (!fn_db_version_) {
        shim_log("error", "GetProcAddress('akav_db_version') failed");
        return false;
    }

    fn_strerror_ = (pfn_akav_strerror)GetProcAddress(dll_, "akav_strerror");
    if (!fn_strerror_) {
        shim_log("error", "GetProcAddress('akav_strerror') failed");
        return false;
    }

    shim_log("info", "All AV API symbols resolved successfully");
    return true;
}

#undef RESOLVE_SYM

/* ── Init / Shutdown ───────────────────────────────────────────── */

bool AVEngine::init(const char* config_path)
{
    /* Parse config first (sets dll_path_, db_path_, etc.) */
    parse_config(config_path);

    /* Load the DLL */
    if (!load_dll())
        return false;  /* Graceful degradation — logged already */

    /* Resolve all API symbols */
    if (!resolve_symbols()) {
        shim_log("error", "Symbol resolution failed — unloading DLL");
        FreeLibrary(dll_);
        dll_ = NULL;
        return false;
    }

    /* Create engine */
    akav_error_t err = fn_create_(&engine_);
    if (err != EDR_AKAV_OK) {
        shim_log("error", "akav_engine_create failed: %d", err);
        engine_ = nullptr;
        FreeLibrary(dll_);
        dll_ = NULL;
        return false;
    }

    /* Initialize engine */
    err = fn_init_(engine_, nullptr);
    if (err != EDR_AKAV_OK) {
        shim_log("error", "akav_engine_init failed: %s",
                 fn_strerror_ ? fn_strerror_(err) : "unknown");
        fn_destroy_(engine_);
        engine_ = nullptr;
        FreeLibrary(dll_);
        dll_ = NULL;
        return false;
    }

    /* Load signatures if DB path configured */
    if (!db_path_.empty()) {
        err = fn_load_sigs_(engine_, db_path_.c_str());
        if (err != EDR_AKAV_OK) {
            shim_log("warn", "Signature load from '%s' failed: %s (continuing without)",
                     db_path_.c_str(),
                     fn_strerror_ ? fn_strerror_(err) : "unknown");
            /* Not fatal — heuristics/EICAR still work */
        }
    }

    shim_log("info", "AV engine initialized (version: %s, db: %s)",
             fn_version_ ? fn_version_() : "?",
             (engine_ && fn_db_version_) ? fn_db_version_(engine_) : "none");

    return true;
}

void AVEngine::shutdown()
{
    if (engine_ && fn_destroy_) {
        fn_destroy_(engine_);
        engine_ = nullptr;
    }

    if (dll_) {
        FreeLibrary(dll_);
        dll_ = NULL;
    }

    /* Zero out function pointers */
    fn_create_ = nullptr;
    fn_init_ = nullptr;
    fn_load_sigs_ = nullptr;
    fn_destroy_ = nullptr;
    fn_scan_file_ = nullptr;
    fn_scan_buffer_ = nullptr;
    fn_cache_clear_ = nullptr;
    fn_cache_stats_ = nullptr;
    fn_opts_default_ = nullptr;
    fn_version_ = nullptr;
    fn_db_version_ = nullptr;
    fn_strerror_ = nullptr;
}

/* ── Timeout-guarded scan ──────────────────────────────────────── */

DWORD WINAPI AVEngine::scan_thread_proc(LPVOID param)
{
    ScanWork* work = static_cast<ScanWork*>(param);
    AVEngine* self = work->self;

    if (work->path) {
        /* File scan */
        work->err = self->fn_scan_file_(
            self->engine_, work->path, &work->opts, &work->result);
    } else {
        /* Buffer scan */
        work->err = self->fn_scan_buffer_(
            self->engine_, work->buf, work->buf_len,
            work->name, &work->opts, &work->result);
    }

    return 0;
}

AVTelemetry AVEngine::do_scan_with_timeout(ScanWork* work, bool is_file)
{
    (void)is_file;

    HANDLE thread = CreateThread(NULL, 0, scan_thread_proc, work, 0, NULL);
    if (!thread) {
        shim_log("error", "CreateThread for scan failed: %lu", GetLastError());
        return empty_telemetry(true, false);
    }

    DWORD wait_result = WaitForSingleObject(thread, (DWORD)scan_timeout_ms_);

    if (wait_result == WAIT_TIMEOUT) {
        shim_log("warn", "Scan timed out after %d ms for '%s'",
                 scan_timeout_ms_,
                 work->path ? work->path : (work->name ? work->name : "<buffer>"));

        /* We can't safely terminate the thread (TerminateThread is dangerous),
         * but we detach it and return a timeout result. The scan thread will
         * eventually complete on its own. */
        CloseHandle(thread);
        return empty_telemetry(true, true);
    }

    CloseHandle(thread);

    if (work->err != EDR_AKAV_OK) {
        shim_log("warn", "Scan error %d for '%s': %s",
                 work->err,
                 work->path ? work->path : (work->name ? work->name : "<buffer>"),
                 fn_strerror_ ? fn_strerror_(work->err) : "unknown");
        return empty_telemetry(true, false);
    }

    return make_telemetry(&work->result, true, false);
}

/* ── Scan dispatch ─────────────────────────────────────────────── */

AVTelemetry AVEngine::scan_file(const char* path)
{
    if (!engine_ || !fn_scan_file_)
        return empty_telemetry(false, false);

    ScanWork work{};
    work.self = this;
    work.path = path;
    work.buf = nullptr;
    work.buf_len = 0;
    work.name = nullptr;
    work.err = EDR_AKAV_OK;
    memset(&work.result, 0, sizeof(work.result));

    /* Set up scan options */
    if (fn_opts_default_)
        fn_opts_default_(&work.opts);
    work.opts.heuristic_level = heuristic_level_;
    work.opts.use_heuristics = (heuristic_level_ > 0) ? 1 : 0;

    return do_scan_with_timeout(&work, true);
}

AVTelemetry AVEngine::scan_buffer(const uint8_t* buf, size_t len, const char* name)
{
    if (!engine_ || !fn_scan_buffer_)
        return empty_telemetry(false, false);

    ScanWork work{};
    work.self = this;
    work.path = nullptr;
    work.buf = buf;
    work.buf_len = len;
    work.name = name;
    work.err = EDR_AKAV_OK;
    memset(&work.result, 0, sizeof(work.result));

    if (fn_opts_default_)
        fn_opts_default_(&work.opts);
    work.opts.heuristic_level = heuristic_level_;
    work.opts.use_heuristics = (heuristic_level_ > 0) ? 1 : 0;

    return do_scan_with_timeout(&work, false);
}

/* ── Reload / Cache ────────────────────────────────────────────── */

bool AVEngine::reload_signatures()
{
    if (!engine_ || !fn_load_sigs_ || db_path_.empty())
        return false;

    akav_error_t err = fn_load_sigs_(engine_, db_path_.c_str());
    if (err != EDR_AKAV_OK) {
        shim_log("error", "Signature reload failed: %s",
                 fn_strerror_ ? fn_strerror_(err) : "unknown");
        return false;
    }

    shim_log("info", "Signatures reloaded from '%s'", db_path_.c_str());
    return true;
}

bool AVEngine::cache_stats(uint64_t* hits, uint64_t* misses, uint64_t* entries)
{
    if (!engine_ || !fn_cache_stats_)
        return false;
    return fn_cache_stats_(engine_, hits, misses, entries) == EDR_AKAV_OK;
}

bool AVEngine::cache_clear()
{
    if (!engine_ || !fn_cache_clear_)
        return false;
    return fn_cache_clear_(engine_) == EDR_AKAV_OK;
}

/* ── Version ───────────────────────────────────────────────────── */

const char* AVEngine::engine_version() const
{
    if (fn_version_)
        return fn_version_();
    return "unavailable";
}

const char* AVEngine::db_version() const
{
    if (engine_ && fn_db_version_)
        return fn_db_version_(engine_);
    return "unavailable";
}

/* ── Telemetry construction ────────────────────────────────────── */

AVTelemetry AVEngine::make_telemetry(const edr_akav_scan_result_t* result,
                                     bool available, bool timeout)
{
    AVTelemetry t{};
    t.av_available = available;
    t.av_timeout = timeout;
    t.av_detected = (result->found != 0);
    t.av_heuristic_score = result->heuristic_score;
    t.av_scan_cached = (result->cached != 0);
    t.av_scan_time_ms = result->scan_time_ms;
    t.av_in_whitelist = (result->in_whitelist != 0);

    strncpy_s(t.av_malware_name, sizeof(t.av_malware_name),
              result->malware_name, _TRUNCATE);
    strncpy_s(t.av_signature_id, sizeof(t.av_signature_id),
              result->signature_id, _TRUNCATE);
    strncpy_s(t.av_scanner_id, sizeof(t.av_scanner_id),
              result->scanner_id, _TRUNCATE);
    strncpy_s(t.av_file_type, sizeof(t.av_file_type),
              result->file_type, _TRUNCATE);

    return t;
}

AVTelemetry AVEngine::empty_telemetry(bool available, bool timeout)
{
    AVTelemetry t{};
    t.av_available = available;
    t.av_timeout = timeout;
    t.av_detected = false;
    t.av_heuristic_score = 0.0;
    t.av_scan_cached = false;
    t.av_scan_time_ms = 0;
    t.av_in_whitelist = false;
    t.av_malware_name[0] = '\0';
    t.av_signature_id[0] = '\0';
    t.av_scanner_id[0] = '\0';
    t.av_file_type[0] = '\0';
    return t;
}
