/*
 * sentinel-agent/json_writer.h
 * JSON-lines event log writer with automatic rotation.
 *
 * Serializes SENTINEL_EVENT structs into JSON-lines format (one JSON object
 * per line). Automatically rotates the log file when it exceeds
 * the configured max size (default 100 MB).
 *
 * P4-T2: Event Processing & JSON Logging.
 */

#ifndef SENTINEL_JSON_WRITER_H
#define SENTINEL_JSON_WRITER_H

#include <windows.h>
#include <string>
#include <mutex>
#include "telemetry.h"

class JsonWriter {
public:
    JsonWriter();
    ~JsonWriter();

    /*
     * Open or create the log file at the given path.
     * maxSizeBytes: rotate when file exceeds this size.
     */
    bool Open(const char* basePath, UINT32 maxSizeBytes);

    /*
     * Serialize an event to JSON and write as a single line.
     * parentImagePath is the enriched parent process image path
     * (empty string if unknown).
     */
    void WriteEvent(const SENTINEL_EVENT& evt, const std::wstring& parentImagePath);

    /* Flush and close the log file. */
    void Close();

    /* Current bytes written to the active log file. */
    ULONGLONG BytesWritten() const { return m_bytesWritten; }

    /*
     * Serialize an event to a JSON string (no trailing newline).
     * Public static so other output writers (e.g. SIEM) can reuse.
     * P9-T5: SIEM Integration.
     */
    static std::string SerializeEvent(const SENTINEL_EVENT& evt,
                                       const std::wstring& parentImagePath);

    /* String helpers — public static for shared use */
    static std::string EscapeJson(const std::string& s);
    static std::string WcharToUtf8(const WCHAR* ws);
    static std::string GuidToString(const GUID& guid);
    static std::string TimestampToIso8601(const LARGE_INTEGER& ts);
    static std::string PointerToHex(ULONG_PTR ptr);
    static std::string DwordToHex(ULONG val);

private:
    HANDLE      m_hFile;
    std::string m_basePath;
    ULONGLONG   m_bytesWritten;
    UINT32      m_maxSizeBytes;
    int         m_rotationIndex;
    std::mutex  m_mutex;

    void RotateIfNeeded();
    void ReopenFile();

    /* Serialization helpers (static — no instance state needed) */
    static std::string EventToJson(const SENTINEL_EVENT& evt,
                                    const std::wstring& parentImagePath);
    static std::string ProcessCtxToJson(const SENTINEL_PROCESS_CTX& ctx,
                                         const std::wstring& parentImagePath);
    static std::string PayloadToJson(const SENTINEL_EVENT& evt);

    /* Per-payload serializers */
    static std::string HookPayloadToJson(const SENTINEL_HOOK_EVENT& hook);
    static std::string ProcessPayloadToJson(const SENTINEL_PROCESS_EVENT& proc);
    static std::string ThreadPayloadToJson(const SENTINEL_THREAD_EVENT& thread);
    static std::string ObjectPayloadToJson(const SENTINEL_OBJECT_EVENT& obj);
    static std::string ImageLoadPayloadToJson(const SENTINEL_IMAGELOAD_EVENT& img);
    static std::string RegistryPayloadToJson(const SENTINEL_REGISTRY_EVENT& reg);
    static std::string FilePayloadToJson(const SENTINEL_FILE_EVENT& file);
    static std::string PipePayloadToJson(const SENTINEL_PIPE_EVENT& pipe);
    static std::string NetworkPayloadToJson(const SENTINEL_NETWORK_EVENT& net);
    static std::string AmsiPayloadToJson(const SENTINEL_AMSI_EVENT& amsi);
    static std::string AlertPayloadToJson(const SENTINEL_ALERT_EVENT& alert);
    static std::string TamperPayloadToJson(const SENTINEL_TAMPER_EVENT& tamper);
    static std::string EtwPayloadToJson(const SENTINEL_ETW_EVENT& etw);
    static std::string ScannerPayloadToJson(const SENTINEL_SCANNER_EVENT& scan);
};

/* ── Name lookup functions ───────────────────────────────────────────────── */

const char* SourceName(int src);
const char* SeverityName(int sev);
const char* HookFunctionName(int func);

#endif /* SENTINEL_JSON_WRITER_H */
