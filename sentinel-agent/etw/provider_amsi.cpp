/*
 * sentinel-agent/etw/provider_amsi.cpp
 * Parser for Microsoft-Antimalware-Scan-Interface ETW events.
 *
 * Captures AMSI scan events for passive observation of antimalware scanning.
 * This is critical for detecting:
 *   - Obfuscated PowerShell that triggers AMSI detection
 *   - Fileless malware scanned in-memory
 *   - Script-based attacks (VBScript, JScript, macros)
 *   - AMSI bypass attempts (if scan results show anomalies)
 *
 * Supported event IDs:
 *   1101 — AMSI Scan (fires when any AMSI-instrumented app submits content)
 *
 * UserData layout (TraceLogging, verified via hex dump):
 *     Offset 0:  UINT64  Session        (monotonic scan session ID)
 *     Offset 8:  UINT8   ScanStatus     (1 = success)
 *     Offset 9:  INT32   ScanResult     (AMSI_RESULT: 0=Clean, 1=NotDetected, 32768=Detected)
 *     Offset 13: WCHAR[] AppName        (null-terminated, e.g. "PowerShell_C:\...\powershell.exe")
 *     After null: WCHAR[] ContentName   (null-terminated, script name or identifier)
 *     Then:       UINT32  ContentSize
 *     Then:       UINT32  OriginalSize
 *     Then:       BYTE[]  Content       (the scanned content blob — variable length)
 *     Then:       BYTE[]  Hash
 *     Then:       BOOLEAN ContentFiltered
 *
 * NOTE: AMSI events route through Payload.Amsi (SentinelSourceAmsi),
 * not Payload.Etw, reusing the existing SENTINEL_AMSI_EVENT struct.
 *
 * P7-T3: AMSI + RPC + Kernel-Process ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#include "provider_amsi.h"
#include <cstring>
#include <cstdio>

/* ── AMSI ETW event IDs ───────────────────────────────────────────────── */

#define AMSI_EVENT_SCAN     1101

/*
 * Fixed header size before the AppName string:
 *   Session(8) + ScanStatus(1) + ScanResult(4) = 13 bytes
 */
#define AMSI_HEADER_SIZE    13

/* ── AMSI_RESULT values from the ETW provider ─────────────────────────── */

/*
 * Raw AMSI_RESULT values from the Windows AMSI API:
 *   0     = AMSI_RESULT_CLEAN
 *   1     = AMSI_RESULT_NOT_DETECTED
 *   16384 = AMSI_RESULT_BLOCKED_BY_ADMIN_START
 *   20480 = AMSI_RESULT_BLOCKED_BY_ADMIN_END
 *   32768 = AMSI_RESULT_DETECTED
 *
 * We map these to our SENTINEL_AMSI_RESULT enum for consistency.
 */
static SENTINEL_AMSI_RESULT
MapAmsiResult(LONG rawResult)
{
    if (rawResult == 0)
        return SentinelAmsiClean;
    if (rawResult == 1)
        return SentinelAmsiSuspicious;       /* Not detected = informational */
    if (rawResult >= 32768)
        return SentinelAmsiMalware;
    if (rawResult >= 16384)
        return SentinelAmsiBlocked;
    return SentinelAmsiSuspicious;
}

/* ── Helper: scan past a null-terminated WCHAR string in UserData ──────── */

/*
 * Returns pointer to byte after the null terminator, or NULL if no
 * terminator found within bounds.
 */
static const BYTE*
SkipWcharString(const BYTE* ptr, const BYTE* end, const WCHAR** outStr)
{
    const WCHAR* str   = (const WCHAR*)ptr;
    size_t maxChars    = (end - ptr) / sizeof(WCHAR);

    for (size_t i = 0; i < maxChars; i++) {
        if (str[i] == L'\0') {
            if (outStr) *outStr = str;
            return ptr + (i + 1) * sizeof(WCHAR);
        }
    }
    return nullptr;
}

/* ── ParseAmsiEvent ───────────────────────────────────────────────────── */

bool
ParseAmsiEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent)
{
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    if (eventId != AMSI_EVENT_SCAN) {
        return false;
    }

    /*
     * Need at least the 13-byte header + one WCHAR for AppName.
     */
    if (pEvent->UserDataLength < AMSI_HEADER_SIZE + sizeof(WCHAR)) {
        return false;
    }

    const BYTE* data    = (const BYTE*)pEvent->UserData;
    const BYTE* dataEnd = data + pEvent->UserDataLength;

    /* ── Parse fixed header ────────────────────────────────────────── */

    /* UINT64 session at offset 0 — skip (not needed for telemetry) */

    /* UINT8 scanStatus at offset 8 — skip */

    /* INT32 scanResult at offset 9 */
    LONG scanResult = *(const LONG*)(data + 9);

    /* ── Extract AppName (null-terminated WCHAR string at offset 13) ── */

    const WCHAR* appName = nullptr;
    const BYTE*  ptr     = SkipWcharString(data + AMSI_HEADER_SIZE, dataEnd, &appName);

    if (!ptr || !appName) {
        return false;
    }

    /* ── Extract ContentName (next null-terminated WCHAR string) ───── */

    const WCHAR* contentName = nullptr;
    const BYTE*  ptr2        = SkipWcharString(ptr, dataEnd, &contentName);

    /* ── Extract ContentSize (UINT32 after ContentName) ────────────── */

    ULONG contentSize = 0;
    if (ptr2 && ptr2 + sizeof(ULONG) <= dataEnd) {
        contentSize = *(const ULONG*)ptr2;
    }

    /* ── Populate the SENTINEL_EVENT ───────────────────────────────── */

    memset(outEvent, 0, sizeof(SENTINEL_EVENT));

    /* Pseudo-GUID */
    {
        LARGE_INTEGER ts;
        static volatile LONG s_amsiSeqNum = 0;
        QueryPerformanceCounter(&ts);
        outEvent->EventId.Data1 = pEvent->EventHeader.ProcessId;
        outEvent->EventId.Data2 = (USHORT)GetCurrentProcessorNumber();
        outEvent->EventId.Data3 = (USHORT)InterlockedIncrement(&s_amsiSeqNum);
        *(LONGLONG*)outEvent->EventId.Data4 = ts.QuadPart;
    }

    outEvent->Timestamp.QuadPart = pEvent->EventHeader.TimeStamp.QuadPart;
    outEvent->Source   = SentinelSourceAmsi;   /* Routes through Payload.Amsi */
    outEvent->Severity = SentinelSeverityInformational;

    outEvent->ProcessCtx.ProcessId = pEvent->EventHeader.ProcessId;

    /* AMSI payload (NOT ETW payload — uses Payload.Amsi) */
    SENTINEL_AMSI_EVENT* amsi = &outEvent->Payload.Amsi;

    /* Copy AppName */
    size_t appLen = wcslen(appName);
    if (appLen >= SENTINEL_MAX_PATH) appLen = SENTINEL_MAX_PATH - 1;
    memcpy(amsi->AppName, appName, appLen * sizeof(WCHAR));
    amsi->AppName[appLen] = L'\0';

    amsi->ContentSize = contentSize;
    amsi->ScanResult  = MapAmsiResult(scanResult);

    /* Store ContentName in MatchedRule field (repurposed as identifier) */
    if (contentName) {
        size_t cnLen = wcslen(contentName);
        if (cnLen >= SENTINEL_MAX_RULE_NAME) cnLen = SENTINEL_MAX_RULE_NAME - 1;
        memcpy(amsi->MatchedRule, contentName, cnLen * sizeof(WCHAR));
        amsi->MatchedRule[cnLen] = L'\0';
    }

    return true;
}
