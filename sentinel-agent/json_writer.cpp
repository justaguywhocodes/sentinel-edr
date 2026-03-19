/*
 * sentinel-agent/json_writer.cpp
 * JSON-lines event log writer implementation.
 *
 * P4-T2: Event Processing & JSON Logging.
 */

#include "json_writer.h"
#include "constants.h"
#include <cstdio>
#include <cstring>
#include <sstream>
#include <iomanip>

/* ── Name lookup tables ──────────────────────────────────────────────────── */

static const char* g_SourceNames[] = {
    "DriverProcess", "DriverThread", "DriverObject",
    "DriverImageLoad", "DriverRegistry", "DriverMinifilter",
    "DriverNetwork", "HookDll", "Etw", "Amsi",
    "Scanner", "RuleEngine", "SelfProtect", "DriverPipe",
};

static const char* g_SeverityNames[] = {
    "Informational", "Low", "Medium", "High", "Critical",
};

static const char* g_HookFuncNames[] = {
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtCreateThreadEx",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtQueueApcThread",
    "NtOpenProcess",
    "NtSuspendThread",
    "NtResumeThread",
    "NtCreateSection",
    "NtCreateNamedPipeFile",
};

static const char* g_RegOpNames[] = {
    "CreateKey", "OpenKey", "SetValue", "DeleteValue", "DeleteKey", "RenameKey",
};

static const char* g_FileOpNames[] = {
    "Create", "Write", "Rename", "Delete", "SetInfo",
};

static const char* g_ObjOpNames[] = {
    "Create", "Duplicate",
};

static const char* g_ObjTypeNames[] = {
    "Process", "Thread",
};

static const char* g_AmsiResultNames[] = {
    "Clean", "Suspicious", "Malware", "Blocked",
};

static const char* g_TamperTypeNames[] = {
    "HookRemoved", "CallbackRemoved", "EtwSessionStopped",
    "AmsiPatched", "DirectSyscall", "NtdllRemap",
};

static const char* g_EtwProviderNames[] = {
    "DotNETRuntime", "PowerShell", "DnsClient", "Kerberos",
    "Services", "AMSI", "RPC", "KernelProcess",
};

static const char*
SafeLookup(const char* table[], int count, int index)
{
    if (index >= 0 && index < count) {
        return table[index];
    }
    return "Unknown";
}

const char* SourceName(int src)
{
    return SafeLookup(g_SourceNames,
        (int)(sizeof(g_SourceNames) / sizeof(g_SourceNames[0])), src);
}

const char* SeverityName(int sev)
{
    return SafeLookup(g_SeverityNames,
        (int)(sizeof(g_SeverityNames) / sizeof(g_SeverityNames[0])), sev);
}

const char* HookFunctionName(int func)
{
    return SafeLookup(g_HookFuncNames,
        (int)(sizeof(g_HookFuncNames) / sizeof(g_HookFuncNames[0])), func);
}

/* ── String helpers ──────────────────────────────────────────────────────── */

std::string
JsonWriter::EscapeJson(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "\\u%04x", (unsigned)c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

std::string
JsonWriter::WcharToUtf8(const WCHAR* ws)
{
    if (ws == nullptr || ws[0] == L'\0') {
        return {};
    }

    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};

    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::string
JsonWriter::GuidToString(const GUID& guid)
{
    char buf[40];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buf;
}

std::string
JsonWriter::TimestampToIso8601(const LARGE_INTEGER& ts)
{
    /* Convert Windows FILETIME to SYSTEMTIME */
    FILETIME ft;
    ft.dwLowDateTime  = ts.LowPart;
    ft.dwHighDateTime = (DWORD)ts.HighPart;

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) {
        return "1970-01-01T00:00:00.000Z";
    }

    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

std::string
JsonWriter::PointerToHex(ULONG_PTR ptr)
{
    char buf[24];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llx", (unsigned long long)ptr);
    return buf;
}

std::string
JsonWriter::DwordToHex(ULONG val)
{
    char buf[16];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%lx", val);
    return buf;
}

/* ── JsonWriter lifecycle ────────────────────────────────────────────────── */

JsonWriter::JsonWriter()
    : m_hFile(INVALID_HANDLE_VALUE)
    , m_bytesWritten(0)
    , m_maxSizeBytes(100 * 1024 * 1024)
    , m_rotationIndex(0)
{}

JsonWriter::~JsonWriter()
{
    Close();
}

bool
JsonWriter::Open(const char* basePath, UINT32 maxSizeBytes)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_basePath = basePath;
    m_bytesWritten = 0;
    m_maxSizeBytes = maxSizeBytes;
    m_rotationIndex = 0;

    m_hFile = CreateFileA(
        m_basePath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (m_hFile == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "JsonWriter: Failed to open %s (error %lu)\n",
                     m_basePath.c_str(), GetLastError());
        return false;
    }

    /* Get current file size for rotation tracking */
    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(m_hFile, &fileSize)) {
        m_bytesWritten = fileSize.QuadPart;
    }

    return true;
}

void
JsonWriter::Close()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_hFile);
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
}

void
JsonWriter::ReopenFile()
{
    if (m_hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_hFile);
        CloseHandle(m_hFile);
    }

    m_hFile = CreateFileA(
        m_basePath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    m_bytesWritten = 0;
}

void
JsonWriter::RotateIfNeeded()
{
    if (m_bytesWritten < m_maxSizeBytes) {
        return;
    }

    /* Close the current file */
    if (m_hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(m_hFile);
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }

    /* Shift older rotated files: .3 → .4, .2 → .3, .1 → .2 */
    for (int i = 3; i >= 1; i--) {
        char oldName[MAX_PATH], newName[MAX_PATH];
        _snprintf_s(oldName, sizeof(oldName), _TRUNCATE, "%s.%d",
                     m_basePath.c_str(), i);
        _snprintf_s(newName, sizeof(newName), _TRUNCATE, "%s.%d",
                     m_basePath.c_str(), i + 1);
        MoveFileExA(oldName, newName, MOVEFILE_REPLACE_EXISTING);
    }

    /* Current → .1 */
    char rotatedName[MAX_PATH];
    _snprintf_s(rotatedName, sizeof(rotatedName), _TRUNCATE, "%s.1",
                 m_basePath.c_str());
    MoveFileExA(m_basePath.c_str(), rotatedName, MOVEFILE_REPLACE_EXISTING);

    m_rotationIndex++;

    /* Reopen fresh file */
    ReopenFile();
}

/* ── Event serialization ─────────────────────────────────────────────────── */

std::string
JsonWriter::SerializeEvent(const SENTINEL_EVENT& evt,
                            const std::wstring& parentImagePath)
{
    return EventToJson(evt, parentImagePath);
}

void
JsonWriter::WriteEvent(const SENTINEL_EVENT& evt,
                       const std::wstring& parentImagePath)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    std::string json = EventToJson(evt, parentImagePath);
    json += '\n';

    DWORD written = 0;
    WriteFile(m_hFile, json.c_str(), (DWORD)json.size(), &written, nullptr);
    m_bytesWritten += written;

    RotateIfNeeded();
}

std::string
JsonWriter::EventToJson(const SENTINEL_EVENT& evt,
                        const std::wstring& parentImagePath)
{
    std::string json;
    json.reserve(1024);

    json += "{\"eventId\":\"";
    json += GuidToString(evt.EventId);
    json += "\",\"timestamp\":\"";
    json += TimestampToIso8601(evt.Timestamp);
    json += "\",\"source\":\"";
    json += SourceName(evt.Source);
    json += "\",\"severity\":\"";
    json += SeverityName(evt.Severity);
    json += "\",\"process\":";
    json += ProcessCtxToJson(evt.ProcessCtx, parentImagePath);
    json += ",\"payload\":";
    json += PayloadToJson(evt);
    json += '}';

    return json;
}

std::string
JsonWriter::ProcessCtxToJson(const SENTINEL_PROCESS_CTX& ctx,
                              const std::wstring& parentImagePath)
{
    std::string json;
    json.reserve(512);

    char numBuf[32];

    json += "{\"pid\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", ctx.ProcessId);
    json += numBuf;

    json += ",\"parentPid\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", ctx.ParentProcessId);
    json += numBuf;

    json += ",\"threadId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", ctx.ThreadId);
    json += numBuf;

    json += ",\"sessionId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", ctx.SessionId);
    json += numBuf;

    json += ",\"imagePath\":\"";
    json += EscapeJson(WcharToUtf8(ctx.ImagePath));
    json += "\"";

    json += ",\"commandLine\":\"";
    json += EscapeJson(WcharToUtf8(ctx.CommandLine));
    json += "\"";

    json += ",\"userSid\":\"";
    json += EscapeJson(WcharToUtf8(ctx.UserSid));
    json += "\"";

    json += ",\"integrityLevel\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", ctx.IntegrityLevel);
    json += numBuf;

    json += ",\"isElevated\":";
    json += ctx.IsElevated ? "true" : "false";

    if (!parentImagePath.empty()) {
        json += ",\"parentImagePath\":\"";
        json += EscapeJson(WcharToUtf8(parentImagePath.c_str()));
        json += "\"";
    }

    json += '}';
    return json;
}

/* ── Payload serializers ─────────────────────────────────────────────────── */

std::string
JsonWriter::PayloadToJson(const SENTINEL_EVENT& evt)
{
    switch (evt.Source) {
    case SentinelSourceHookDll:
        return HookPayloadToJson(evt.Payload.Hook);
    case SentinelSourceDriverProcess:
        return ProcessPayloadToJson(evt.Payload.Process);
    case SentinelSourceDriverThread:
        return ThreadPayloadToJson(evt.Payload.Thread);
    case SentinelSourceDriverObject:
        return ObjectPayloadToJson(evt.Payload.Object);
    case SentinelSourceDriverImageLoad:
        return ImageLoadPayloadToJson(evt.Payload.ImageLoad);
    case SentinelSourceDriverRegistry:
        return RegistryPayloadToJson(evt.Payload.Registry);
    case SentinelSourceDriverMinifilter:
        return FilePayloadToJson(evt.Payload.File);
    case SentinelSourceDriverPipe:
        return PipePayloadToJson(evt.Payload.Pipe);
    case SentinelSourceDriverNetwork:
        return NetworkPayloadToJson(evt.Payload.Network);
    case SentinelSourceAmsi:
        return AmsiPayloadToJson(evt.Payload.Amsi);
    case SentinelSourceEtw:
        return EtwPayloadToJson(evt.Payload.Etw);
    case SentinelSourceRuleEngine:
        return AlertPayloadToJson(evt.Payload.Alert);
    case SentinelSourceSelfProtect:
        return TamperPayloadToJson(evt.Payload.Tamper);
    case SentinelSourceScanner:
        return ScannerPayloadToJson(evt.Payload.Scanner);
    default:
        return "{}";
    }
}

std::string
JsonWriter::HookPayloadToJson(const SENTINEL_HOOK_EVENT& hook)
{
    std::string json;
    char numBuf[32];

    json += "{\"function\":\"";
    json += HookFunctionName(hook.Function);
    json += "\"";

    /*
     * NtCreateNamedPipeFile repurposes fields:
     *   CallingModule → pipe name
     *   Protection    → isSuspicious (0 or 1)
     *   AllocationType → DesiredAccess
     */
    if (hook.Function == SentinelHookNtCreateNamedPipeFile) {
        json += ",\"pipeName\":\"";
        json += EscapeJson(WcharToUtf8(hook.CallingModule));
        json += "\"";

        if (hook.Protection) {
            json += ",\"isSuspicious\":true";
        }

        json += ",\"desiredAccess\":\"";
        json += DwordToHex(hook.AllocationType);
        json += "\"";

        json += ",\"returnStatus\":\"";
        json += DwordToHex(hook.ReturnStatus);
        json += "\"";

        json += '}';
        return json;
    }

    json += ",\"targetPid\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", hook.TargetProcessId);
    json += numBuf;

    json += ",\"baseAddress\":\"";
    json += PointerToHex(hook.BaseAddress);
    json += "\"";

    json += ",\"regionSize\":\"";
    json += PointerToHex(hook.RegionSize);
    json += "\"";

    json += ",\"protection\":\"";
    json += DwordToHex(hook.Protection);
    json += "\"";

    json += ",\"allocationType\":\"";
    json += DwordToHex(hook.AllocationType);
    json += "\"";

    json += ",\"returnAddress\":\"";
    json += PointerToHex(hook.ReturnAddress);
    json += "\"";

    json += ",\"callingModule\":\"";
    json += EscapeJson(WcharToUtf8(hook.CallingModule));
    json += "\"";

    json += ",\"stackHash\":\"";
    json += DwordToHex(hook.StackHash);
    json += "\"";

    json += ",\"returnStatus\":\"";
    json += DwordToHex(hook.ReturnStatus);
    json += "\"";

    json += '}';
    return json;
}

std::string
JsonWriter::ProcessPayloadToJson(const SENTINEL_PROCESS_EVENT& proc)
{
    std::string json;
    char numBuf[32];

    json += "{\"isCreate\":";
    json += proc.IsCreate ? "true" : "false";

    json += ",\"newProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", proc.NewProcessId);
    json += numBuf;

    json += ",\"parentProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", proc.ParentProcessId);
    json += numBuf;

    json += ",\"imagePath\":\"";
    json += EscapeJson(WcharToUtf8(proc.ImagePath));
    json += "\"";

    json += ",\"commandLine\":\"";
    json += EscapeJson(WcharToUtf8(proc.CommandLine));
    json += "\"";

    json += ",\"integrityLevel\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", proc.IntegrityLevel);
    json += numBuf;

    json += ",\"isElevated\":";
    json += proc.IsElevated ? "true" : "false";

    if (!proc.IsCreate) {
        json += ",\"exitStatus\":\"";
        json += DwordToHex(proc.ExitStatus);
        json += "\"";
    }

    json += '}';
    return json;
}

std::string
JsonWriter::ThreadPayloadToJson(const SENTINEL_THREAD_EVENT& thread)
{
    std::string json;
    char numBuf[32];

    json += "{\"isCreate\":";
    json += thread.IsCreate ? "true" : "false";

    json += ",\"threadId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", thread.ThreadId);
    json += numBuf;

    json += ",\"owningProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", thread.OwningProcessId);
    json += numBuf;

    json += ",\"creatingProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", thread.CreatingProcessId);
    json += numBuf;

    json += ",\"startAddress\":\"";
    json += PointerToHex(thread.StartAddress);
    json += "\"";

    json += ",\"isRemote\":";
    json += thread.IsRemote ? "true" : "false";

    json += '}';
    return json;
}

std::string
JsonWriter::ObjectPayloadToJson(const SENTINEL_OBJECT_EVENT& obj)
{
    std::string json;
    char numBuf[32];

    json += "{\"operation\":\"";
    json += SafeLookup(g_ObjOpNames,
        (int)(sizeof(g_ObjOpNames) / sizeof(g_ObjOpNames[0])), obj.Operation);
    json += "\"";

    json += ",\"objectType\":\"";
    json += SafeLookup(g_ObjTypeNames,
        (int)(sizeof(g_ObjTypeNames) / sizeof(g_ObjTypeNames[0])), obj.ObjectType);
    json += "\"";

    json += ",\"sourceProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", obj.SourceProcessId);
    json += numBuf;

    json += ",\"targetProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", obj.TargetProcessId);
    json += numBuf;

    json += ",\"targetImagePath\":\"";
    json += EscapeJson(WcharToUtf8(obj.TargetImagePath));
    json += "\"";

    json += ",\"desiredAccess\":\"";
    json += DwordToHex(obj.DesiredAccess);
    json += "\"";

    json += ",\"grantedAccess\":\"";
    json += DwordToHex(obj.GrantedAccess);
    json += "\"";

    json += '}';
    return json;
}

std::string
JsonWriter::ImageLoadPayloadToJson(const SENTINEL_IMAGELOAD_EVENT& img)
{
    std::string json;
    char numBuf[32];

    json += "{\"processId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", img.ProcessId);
    json += numBuf;

    json += ",\"imagePath\":\"";
    json += EscapeJson(WcharToUtf8(img.ImagePath));
    json += "\"";

    json += ",\"imageBase\":\"";
    json += PointerToHex(img.ImageBase);
    json += "\"";

    json += ",\"imageSize\":\"";
    json += PointerToHex(img.ImageSize);
    json += "\"";

    json += ",\"isKernelImage\":";
    json += img.IsKernelImage ? "true" : "false";

    json += ",\"isSigned\":";
    json += img.IsSigned ? "true" : "false";

    json += ",\"isSignatureValid\":";
    json += img.IsSignatureValid ? "true" : "false";

    json += '}';
    return json;
}

std::string
JsonWriter::RegistryPayloadToJson(const SENTINEL_REGISTRY_EVENT& reg)
{
    std::string json;

    json += "{\"operation\":\"";
    json += SafeLookup(g_RegOpNames,
        (int)(sizeof(g_RegOpNames) / sizeof(g_RegOpNames[0])), reg.Operation);
    json += "\"";

    json += ",\"keyPath\":\"";
    json += EscapeJson(WcharToUtf8(reg.KeyPath));
    json += "\"";

    json += ",\"valueName\":\"";
    json += EscapeJson(WcharToUtf8(reg.ValueName));
    json += "\"";

    char numBuf[32];
    json += ",\"dataType\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", reg.DataType);
    json += numBuf;

    json += ",\"dataSize\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", reg.DataSize);
    json += numBuf;

    json += '}';
    return json;
}

std::string
JsonWriter::FilePayloadToJson(const SENTINEL_FILE_EVENT& file)
{
    std::string json;
    char numBuf[32];

    json += "{\"operation\":\"";
    json += SafeLookup(g_FileOpNames,
        (int)(sizeof(g_FileOpNames) / sizeof(g_FileOpNames[0])), file.Operation);
    json += "\"";

    json += ",\"processId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", file.RequestingProcessId);
    json += numBuf;

    json += ",\"filePath\":\"";
    json += EscapeJson(WcharToUtf8(file.FilePath));
    json += "\"";

    if (file.NewFilePath[0] != L'\0') {
        json += ",\"newFilePath\":\"";
        json += EscapeJson(WcharToUtf8(file.NewFilePath));
        json += "\"";
    }

    json += ",\"fileSize\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lld", file.FileSize.QuadPart);
    json += numBuf;

    if (file.Sha256Hex[0] != '\0') {
        json += ",\"sha256\":\"";
        json += file.Sha256Hex;
        json += "\"";
    }

    if (file.HashSkipped) {
        json += ",\"hashSkipped\":true";
    }

    json += '}';
    return json;
}

std::string
JsonWriter::PipePayloadToJson(const SENTINEL_PIPE_EVENT& pipe)
{
    std::string json;
    char numBuf[32];

    json += "{\"pipeName\":\"";
    json += EscapeJson(WcharToUtf8(pipe.PipeName));
    json += "\"";

    json += ",\"creatingProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", pipe.CreatingProcessId);
    json += numBuf;

    json += ",\"accessMode\":\"";
    json += DwordToHex(pipe.AccessMode);
    json += "\"";

    if (pipe.IsSuspicious) {
        json += ",\"isSuspicious\":true";
    }

    json += '}';
    return json;
}

std::string
JsonWriter::NetworkPayloadToJson(const SENTINEL_NETWORK_EVENT& net)
{
    std::string json;
    char numBuf[32];

    json += "{\"direction\":\"";
    json += (net.Direction == SentinelNetOutbound) ? "Outbound" : "Inbound";
    json += "\"";

    json += ",\"processId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", net.ProcessId);
    json += numBuf;

    json += ",\"protocol\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", net.Protocol);
    json += numBuf;

    /* Format IPs as dotted decimal */
    ULONG la = net.LocalAddr, ra = net.RemoteAddr;
    char ipBuf[24];
    _snprintf_s(ipBuf, sizeof(ipBuf), _TRUNCATE, "%u.%u.%u.%u",
        la & 0xFF, (la >> 8) & 0xFF, (la >> 16) & 0xFF, (la >> 24) & 0xFF);
    json += ",\"localAddr\":\"";
    json += ipBuf;
    json += "\"";

    json += ",\"localPort\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%u", net.LocalPort);
    json += numBuf;

    _snprintf_s(ipBuf, sizeof(ipBuf), _TRUNCATE, "%u.%u.%u.%u",
        ra & 0xFF, (ra >> 8) & 0xFF, (ra >> 16) & 0xFF, (ra >> 24) & 0xFF);
    json += ",\"remoteAddr\":\"";
    json += ipBuf;
    json += "\"";

    json += ",\"remotePort\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%u", net.RemotePort);
    json += numBuf;

    json += '}';
    return json;
}

std::string
JsonWriter::AmsiPayloadToJson(const SENTINEL_AMSI_EVENT& amsi)
{
    std::string json;
    char numBuf[32];

    json += "{\"appName\":\"";
    json += EscapeJson(WcharToUtf8(amsi.AppName));
    json += "\"";

    json += ",\"contentSize\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", amsi.ContentSize);
    json += numBuf;

    json += ",\"scanResult\":\"";
    json += SafeLookup(g_AmsiResultNames,
        (int)(sizeof(g_AmsiResultNames) / sizeof(g_AmsiResultNames[0])),
        amsi.ScanResult);
    json += "\"";

    if (amsi.MatchedRule[0] != L'\0') {
        json += ",\"matchedRule\":\"";
        json += EscapeJson(WcharToUtf8(amsi.MatchedRule));
        json += "\"";
    }

    json += '}';
    return json;
}

std::string
JsonWriter::AlertPayloadToJson(const SENTINEL_ALERT_EVENT& alert)
{
    std::string json;

    json += "{\"ruleName\":\"";
    json += EscapeJson(std::string(alert.RuleName));
    json += "\"";

    json += ",\"severity\":\"";
    json += SeverityName(alert.Severity);
    json += "\"";

    json += ",\"triggerSource\":\"";
    json += SourceName(alert.TriggerSource);
    json += "\"";

    json += ",\"triggerEventId\":\"";
    json += GuidToString(alert.TriggerEventId);
    json += "\"";

    json += '}';
    return json;
}

std::string
JsonWriter::TamperPayloadToJson(const SENTINEL_TAMPER_EVENT& tamper)
{
    std::string json;
    char numBuf[32];

    json += "{\"tamperType\":\"";
    json += SafeLookup(g_TamperTypeNames,
        (int)(sizeof(g_TamperTypeNames) / sizeof(g_TamperTypeNames[0])),
        tamper.TamperType);
    json += "\"";

    json += ",\"processId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", tamper.ProcessId);
    json += numBuf;

    json += ",\"detail\":\"";
    json += EscapeJson(WcharToUtf8(tamper.Detail));
    json += "\"";

    json += '}';
    return json;
}

std::string
JsonWriter::EtwPayloadToJson(const SENTINEL_ETW_EVENT& etw)
{
    std::string json;
    char numBuf[32];

    json += "{\"provider\":\"";
    json += SafeLookup(g_EtwProviderNames,
        (int)(sizeof(g_EtwProviderNames) / sizeof(g_EtwProviderNames[0])),
        etw.Provider);
    json += "\"";

    json += ",\"eventId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%u", etw.EventId);
    json += numBuf;

    json += ",\"level\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%u", etw.Level);
    json += numBuf;

    json += ",\"keyword\":\"";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "0x%llx",
        (unsigned long long)etw.Keyword);
    json += numBuf;
    json += "\"";

    json += ",\"processId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", etw.ProcessId);
    json += numBuf;

    json += ",\"threadId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", etw.ThreadId);
    json += numBuf;

    /* Provider-specific fields */
    switch (etw.Provider) {
    case SentinelEtwDotNet:
        json += ",\"assemblyName\":\"";
        json += EscapeJson(WcharToUtf8(etw.u.DotNet.AssemblyName));
        json += "\"";
        if (etw.u.DotNet.ClassName[0] != L'\0') {
            json += ",\"className\":\"";
            json += EscapeJson(WcharToUtf8(etw.u.DotNet.ClassName));
            json += "\"";
        }
        break;

    case SentinelEtwDnsClient:
        json += ",\"queryName\":\"";
        json += EscapeJson(WcharToUtf8(etw.u.Dns.QueryName));
        json += "\"";

        json += ",\"queryType\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%u", etw.u.Dns.QueryType);
        json += numBuf;

        json += ",\"queryStatus\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", etw.u.Dns.QueryStatus);
        json += numBuf;
        break;

    case SentinelEtwPowerShell:
        json += ",\"scriptBlockId\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.PowerShell.ScriptBlockId);
        json += numBuf;

        json += ",\"messageNumber\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.PowerShell.MessageNumber);
        json += numBuf;

        json += ",\"messageTotal\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.PowerShell.MessageTotal);
        json += numBuf;

        json += ",\"scriptBlock\":\"";
        json += EscapeJson(WcharToUtf8(etw.u.PowerShell.ScriptBlock));
        json += "\"";
        break;

    case SentinelEtwKerberos:
        json += ",\"targetName\":\"";
        json += EscapeJson(WcharToUtf8(etw.u.Kerberos.TargetName));
        json += "\"";

        json += ",\"status\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.Kerberos.Status);
        json += numBuf;

        json += ",\"ticketFlags\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.Kerberos.TicketFlags);
        json += numBuf;
        break;

    case SentinelEtwRpc:
    {
        /* Format InterfaceUuid as standard GUID string */
        char guidBuf[64];
        const GUID& iface = etw.u.Rpc.InterfaceUuid;
        _snprintf_s(guidBuf, sizeof(guidBuf), _TRUNCATE,
            "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            iface.Data1, iface.Data2, iface.Data3,
            iface.Data4[0], iface.Data4[1],
            iface.Data4[2], iface.Data4[3],
            iface.Data4[4], iface.Data4[5],
            iface.Data4[6], iface.Data4[7]);

        json += ",\"interfaceUuid\":\"";
        json += guidBuf;
        json += "\"";

        json += ",\"opNum\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.Rpc.OpNum);
        json += numBuf;

        json += ",\"protocol\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.Rpc.Protocol);
        json += numBuf;
        break;
    }

    case SentinelEtwKernelProc:
        json += ",\"parentProcessId\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.KernelProcess.ParentProcessId);
        json += numBuf;

        json += ",\"sessionId\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.KernelProcess.SessionId);
        json += numBuf;

        json += ",\"exitCode\":";
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu",
            etw.u.KernelProcess.ExitCode);
        json += numBuf;

        json += ",\"imageName\":\"";
        json += EscapeJson(WcharToUtf8(etw.u.KernelProcess.ImageName));
        json += "\"";
        break;

    default:
        break;
    }

    json += '}';
    return json;
}

/* ── Scanner payload (P8-T1) ────────────────────────────────────────────── */

std::string
JsonWriter::ScannerPayloadToJson(const SENTINEL_SCANNER_EVENT& scan)
{
    std::string json;
    char numBuf[32];

    static const char* scanTypeNames[] = { "OnAccess", "OnDemand", "Memory" };

    json += "{\"scanType\":\"";
    json += SafeLookup(scanTypeNames,
        (int)(sizeof(scanTypeNames) / sizeof(scanTypeNames[0])),
        scan.ScanType);
    json += "\"";

    json += ",\"targetPath\":\"";
    json += EscapeJson(WcharToUtf8(scan.TargetPath));
    json += "\"";

    json += ",\"targetProcessId\":";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, "%lu", scan.TargetProcessId);
    json += numBuf;

    json += ",\"isMatch\":";
    json += scan.IsMatch ? "true" : "false";

    if (scan.IsMatch && scan.YaraRule[0] != '\0') {
        json += ",\"yaraRule\":\"";
        json += EscapeJson(std::string(scan.YaraRule));
        json += "\"";
    }

    if (scan.Sha256Hex[0] != '\0') {
        json += ",\"sha256\":\"";
        json += scan.Sha256Hex;
        json += "\"";
    }

    json += '}';
    return json;
}
