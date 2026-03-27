/*
 * akesoedr-agent/scanner/av_scanner.cpp
 * AkesoAV integration scanner implementation.
 *
 * Loads akesoav.dll via the edr_shim AVEngine wrapper, registers a
 * SIEM callback to forward native AV events through SiemWriter, and
 * provides on-access file scanning for minifilter events.
 */

#include "av_scanner.h"
#include "../config.h"
#include "../output/siem_writer.h"

#include <cstdio>
#include <cstring>

/* ── NT device path → Win32 path conversion ───────────────────────── */

static bool
NtPathToWin32(const WCHAR* ntPath, WCHAR* win32Path, size_t maxChars)
{
    WCHAR drive[3] = L"A:";
    WCHAR target[512];

    for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
        drive[0] = letter;
        if (QueryDosDeviceW(drive, target, _countof(target)) == 0)
            continue;

        size_t prefixLen = wcslen(target);
        if (_wcsnicmp(ntPath, target, prefixLen) == 0 &&
            ntPath[prefixLen] == L'\\') {
            _snwprintf_s(win32Path, maxChars, _TRUNCATE,
                         L"%s%s", drive, ntPath + prefixLen);
            return true;
        }
    }

    return false;
}

/* ── Init / Shutdown ──────────────────────────────────────────────── */

bool
AVScanner::Init(const AkesoEDRConfig& cfg, SiemWriter* siemWriter)
{
    m_enabled    = cfg.avEnabled;
    m_siemWriter = siemWriter;

    if (!m_enabled) {
        return true;  /* Disabled — not an error */
    }

    /* Initialize AVEngine from the config file.
     * The shim reads [av] section (dll_path, db_path, etc.) itself. */
    if (!m_avEngine.init(cfg.configFilePath)) {
        std::printf("AkesoEDRAgent: WARNING: AV engine init failed "
                    "(AV scanning disabled)\n");
        m_enabled = false;
        return false;
    }

    /* Resolve akav_set_siem_callback from the loaded DLL */
    HMODULE hDll = m_avEngine.dll_handle();
    if (hDll) {
        m_fnSetSiemCallback = (pfn_akav_set_siem_callback)
            GetProcAddress(hDll, "akav_set_siem_callback");
    }

    /* Register SIEM callback if available */
    if (m_fnSetSiemCallback && m_avEngine.engine_handle()) {
        m_fnSetSiemCallback(m_avEngine.engine_handle(),
                            SiemCallbackStatic, this);
        std::printf("AkesoEDRAgent: AV SIEM callback registered\n");
    }

    std::printf("AkesoEDRAgent: AV scanner initialized (engine: %s, db: %s)\n",
                m_avEngine.engine_version(), m_avEngine.db_version());

    return true;
}

void
AVScanner::Shutdown()
{
    m_avEngine.shutdown();
    m_enabled = false;
}

/* ── On-access file scan ──────────────────────────────────────────── */

bool
AVScanner::ScanFile(const AKESOEDR_FILE_EVENT& fileEvt,
                    AKESOEDR_EVENT& alertOut)
{
    if (!m_enabled || !m_avEngine.av_available())
        return false;

    /* Only scan on CREATE and WRITE operations */
    if (fileEvt.Operation != AkesoEDRFileOpCreate &&
        fileEvt.Operation != AkesoEDRFileOpWrite)
        return false;

    /* Skip files where hash was skipped (too large) */
    if (fileEvt.HashSkipped)
        return false;

    /* Convert NT device path to Win32 path */
    WCHAR win32Path[MAX_PATH] = {};
    if (!NtPathToWin32(fileEvt.FilePath, win32Path, MAX_PATH))
        return false;  /* Can't resolve — skip */

    /* Exclude agent's own files to avoid feedback loop */
    if (wcsstr(win32Path, L"\\AkesoEDR\\") != nullptr ||
        wcsstr(win32Path, L"\\AkesoAV\\") != nullptr ||
        wcsstr(win32Path, L"\\AkesoAV") != nullptr)
        return false;

    /* Skip directories */
    DWORD attrs = GetFileAttributesW(win32Path);
    if (attrs == INVALID_FILE_ATTRIBUTES ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY))
        return false;

    /* Check scan cache — skip files already scanned within TTL */
    std::wstring pathKey(win32Path);
    {
        auto it = m_scanCache.find(pathKey);
        if (it != m_scanCache.end()) {
            auto elapsed = std::chrono::steady_clock::now() - it->second.when;
            if (elapsed < std::chrono::seconds(CACHE_TTL_SEC))
                return false;  /* Cached result — skip */
            m_scanCache.erase(it);
        }
    }

    /* Convert wide path to narrow for AV engine */
    char narrowPath[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_UTF8, 0, win32Path, -1,
                        narrowPath, sizeof(narrowPath), nullptr, nullptr);

    AVTelemetry result = m_avEngine.scan_file(narrowPath);

    /* Cache the result regardless of outcome */
    m_scanCache[pathKey] = { std::chrono::steady_clock::now(), result.av_detected };

    if (!result.av_detected)
        return false;

    /* Build an AKESOEDR_EVENT alert for the EDR pipeline */
    AkesoEDREventInit(&alertOut, AkesoEDRSourceScanner, AkesoEDRSeverityHigh);

    alertOut.ProcessCtx.ProcessId = fileEvt.RequestingProcessId;

    auto& scan = alertOut.Payload.Scanner;
    scan.ScanType = AkesoEDRScanOnAccess;
    wcsncpy_s(scan.TargetPath, fileEvt.FilePath, _TRUNCATE);
    scan.IsMatch = TRUE;

    /* Store AV detection name in YaraRule field (reused for AV) */
    _snprintf_s(scan.YaraRule, sizeof(scan.YaraRule), _TRUNCATE,
                "AV:%s", result.av_malware_name);

    /* Copy SHA256 from file event */
    strncpy_s(scan.Sha256Hex, fileEvt.Sha256Hex, _TRUNCATE);

    return true;
}

/* ── SIEM callback ────────────────────────────────────────────────── */

void
AVScanner::SiemCallbackStatic(const void* event, void* user_data)
{
    auto* self = static_cast<AVScanner*>(user_data);
    self->OnSiemEvent(event);
}

void
AVScanner::OnSiemEvent(const void* event)
{
    if (!m_siemWriter) return;

    /* Replicate the akav_siem_event_t layout to avoid build dependency
     * on akesoav.h. Must match the struct in akesoav.h exactly. */
    struct AkavSiemEvent {
        char event_id[64];
        char timestamp[32];
        char source_type[32];
        char event_type[32];
        char agent_id[128];
        char payload_json[8192];
    };

    const auto* avEvt = static_cast<const AkavSiemEvent*>(event);

    /* Build raw NDJSON line preserving the native AV envelope */
    char buf[8704];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"source_type\":\"%s\""
        ",\"event_type\":\"%s\""
        ",\"event_id\":\"%s\""
        ",\"timestamp\":\"%s\""
        ",\"agent_id\":\"%s\""
        ",\"payload\":%s"
        "}",
        avEvt->source_type,
        avEvt->event_type,
        avEvt->event_id,
        avEvt->timestamp,
        avEvt->agent_id,
        avEvt->payload_json);

    m_siemWriter->EnqueueRaw(std::string(buf));
}
