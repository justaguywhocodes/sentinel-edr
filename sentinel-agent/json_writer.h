/*
 * sentinel-agent/json_writer.h
 * JSON-lines event log writer with automatic rotation.
 *
 * Serializes SENTINEL_EVENT structs into JSON-lines format (one JSON object
 * per line). Automatically rotates the log file when it exceeds
 * SENTINEL_LOG_MAX_SIZE_BYTES (100MB).
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

    /* Open or create the log file at the given path. */
    bool Open(const char* basePath);

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

private:
    HANDLE      m_hFile;
    std::string m_basePath;
    ULONGLONG   m_bytesWritten;
    int         m_rotationIndex;
    std::mutex  m_mutex;

    void RotateIfNeeded();
    void ReopenFile();

    /* Serialization helpers */
    std::string EventToJson(const SENTINEL_EVENT& evt,
                            const std::wstring& parentImagePath);
    std::string ProcessCtxToJson(const SENTINEL_PROCESS_CTX& ctx,
                                 const std::wstring& parentImagePath);
    std::string PayloadToJson(const SENTINEL_EVENT& evt);

    /* Per-payload serializers */
    std::string HookPayloadToJson(const SENTINEL_HOOK_EVENT& hook);
    std::string ProcessPayloadToJson(const SENTINEL_PROCESS_EVENT& proc);
    std::string ThreadPayloadToJson(const SENTINEL_THREAD_EVENT& thread);
    std::string ObjectPayloadToJson(const SENTINEL_OBJECT_EVENT& obj);
    std::string ImageLoadPayloadToJson(const SENTINEL_IMAGELOAD_EVENT& img);
    std::string RegistryPayloadToJson(const SENTINEL_REGISTRY_EVENT& reg);
    std::string FilePayloadToJson(const SENTINEL_FILE_EVENT& file);
    std::string PipePayloadToJson(const SENTINEL_PIPE_EVENT& pipe);
    std::string NetworkPayloadToJson(const SENTINEL_NETWORK_EVENT& net);
    std::string AmsiPayloadToJson(const SENTINEL_AMSI_EVENT& amsi);
    std::string AlertPayloadToJson(const SENTINEL_ALERT_EVENT& alert);
    std::string TamperPayloadToJson(const SENTINEL_TAMPER_EVENT& tamper);
    std::string EtwPayloadToJson(const SENTINEL_ETW_EVENT& etw);

    /* String helpers */
    static std::string EscapeJson(const std::string& s);
    static std::string WcharToUtf8(const WCHAR* ws);
    static std::string GuidToString(const GUID& guid);
    static std::string TimestampToIso8601(const LARGE_INTEGER& ts);
    static std::string PointerToHex(ULONG_PTR ptr);
    static std::string DwordToHex(ULONG val);
};

/* ── Name lookup functions ───────────────────────────────────────────────── */

const char* SourceName(int src);
const char* SeverityName(int sev);
const char* HookFunctionName(int func);

#endif /* SENTINEL_JSON_WRITER_H */
