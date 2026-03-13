/*
 * sentinel-agent/etw/provider_powershell.cpp
 * Parser for Microsoft-Windows-PowerShell ETW events.
 *
 * Captures PowerShell command execution events. The raw ETW provider uses
 * event IDs that differ from the Windows Event Log IDs:
 *   - ETW event 7937 = "Command Started" (Event Log maps these to 4103/4104)
 *   - ETW event 7938 = "Command Stopped"
 *
 * Event 7937 UserData is a single null-terminated Unicode string containing
 * a formatted key=value context block:
 *     "        Severity = Informational\r\n"
 *     "        Host Name = ConsoleHost\r\n"
 *     "        Host Version = 5.1.19041.6456\r\n"
 *     "        Host Application = powershell -Command Write-Host hello\r\n"
 *     "        Command Name = Write-Host\r\n"
 *     "        Command Type = Cmdlet\r\n"
 *     "        Script Name = \r\n"
 *     ...
 *
 * We capture the entire context block in ScriptBlock for full visibility,
 * and also extract the "Command Name" field for quick triage.
 *
 * This is critical for detecting:
 *   - Obfuscated/encoded PowerShell (IEX, -EncodedCommand)
 *   - Fileless malware (in-memory script execution)
 *   - Lateral movement tools (Invoke-Mimikatz, PowerView)
 *   - Download cradles (New-Object Net.WebClient)
 *
 * P7-T2: DNS + PowerShell + Kerberos ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#include "provider_powershell.h"
#include <cstring>
#include <cstdio>

/* ── PowerShell ETW event IDs ─────────────────────────────────────────── */

/*
 * Raw ETW event IDs (NOT the Event Log IDs like 4103/4104):
 *   7937 — Command Started: contains full context block with command details
 *   7938 — Command Stopped: completion notification
 */
#define PS_EVENT_COMMAND_STARTED    7937
#define PS_EVENT_COMMAND_STOPPED    7938

/* ── Helper: extract a field value from the key=value context block ────── */

/*
 * Searches for "fieldName = " in the context block and copies the value
 * (up to the next newline or end of string) into outValue.
 * Returns true if the field was found.
 */
static bool
ExtractField(
    const WCHAR* contextBlock,
    const WCHAR* fieldName,
    WCHAR*       outValue,
    size_t       outValueLen
)
{
    /* Build search pattern: "fieldName = " */
    const WCHAR* pos = contextBlock;

    while ((pos = wcsstr(pos, fieldName)) != nullptr) {
        /* Advance past the field name */
        pos += wcslen(fieldName);

        /* Skip " = " separator */
        if (pos[0] == L' ' && pos[1] == L'=' && pos[2] == L' ') {
            pos += 3;
        } else {
            continue;
        }

        /* Copy value up to newline or end */
        size_t i = 0;
        while (i < outValueLen - 1 && pos[i] != L'\0' &&
               pos[i] != L'\r' && pos[i] != L'\n') {
            outValue[i] = pos[i];
            i++;
        }
        outValue[i] = L'\0';
        return (i > 0);
    }

    outValue[0] = L'\0';
    return false;
}

/* ── ParsePowerShellEvent ──────────────────────────────────────────────── */

bool
ParsePowerShellEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent)
{
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    /* Only handle Command Started events — 7938 (stopped) is less useful */
    if (eventId != PS_EVENT_COMMAND_STARTED) {
        return false;
    }

    /*
     * Event 7937 UserData is a single null-terminated Unicode string.
     * No fixed header — the entire payload is the context block text.
     */
    if (pEvent->UserDataLength < sizeof(WCHAR)) {
        return false;
    }

    const WCHAR* contextBlock = (const WCHAR*)pEvent->UserData;
    size_t       maxChars     = pEvent->UserDataLength / sizeof(WCHAR);

    /* Verify null-termination within bounds */
    size_t textLen    = 0;
    bool   terminated = false;

    for (size_t i = 0; i < maxChars; i++) {
        if (contextBlock[i] == L'\0') {
            textLen    = i;
            terminated = true;
            break;
        }
    }

    if (!terminated) {
        textLen = maxChars;
    }

    if (textLen == 0) {
        return false;
    }

    /* ── Populate the SENTINEL_EVENT ─────────────────────────────────── */

    memset(outEvent, 0, sizeof(SENTINEL_EVENT));

    /* Pseudo-GUID */
    {
        LARGE_INTEGER ts;
        static volatile LONG s_psSeqNum = 0;
        QueryPerformanceCounter(&ts);
        outEvent->EventId.Data1 = pEvent->EventHeader.ProcessId;
        outEvent->EventId.Data2 = (USHORT)GetCurrentProcessorNumber();
        outEvent->EventId.Data3 = (USHORT)InterlockedIncrement(&s_psSeqNum);
        *(LONGLONG*)outEvent->EventId.Data4 = ts.QuadPart;
    }

    outEvent->Timestamp.QuadPart = pEvent->EventHeader.TimeStamp.QuadPart;
    outEvent->Source   = SentinelSourceEtw;
    outEvent->Severity = SentinelSeverityInformational;

    outEvent->ProcessCtx.ProcessId = pEvent->EventHeader.ProcessId;

    /* ETW payload */
    SENTINEL_ETW_EVENT* etw = &outEvent->Payload.Etw;
    etw->Provider  = SentinelEtwPowerShell;
    etw->EventId   = pEvent->EventHeader.EventDescriptor.Id;
    etw->Level     = pEvent->EventHeader.EventDescriptor.Level;
    etw->Keyword   = pEvent->EventHeader.EventDescriptor.Keyword;
    etw->ProcessId = pEvent->EventHeader.ProcessId;
    etw->ThreadId  = pEvent->EventHeader.ThreadId;

    /*
     * ScriptBlockId / MessageNumber / MessageTotal don't apply to event 7937.
     * Set MessageNumber=1, MessageTotal=1 to indicate a single complete event.
     */
    etw->u.PowerShell.ScriptBlockId = 0;
    etw->u.PowerShell.MessageNumber = 1;
    etw->u.PowerShell.MessageTotal  = 1;

    /* Copy the full context block into ScriptBlock for maximum visibility */
    size_t copyLen = textLen;
    if (copyLen >= SENTINEL_MAX_SCRIPT_BLOCK) {
        copyLen = SENTINEL_MAX_SCRIPT_BLOCK - 1;
    }
    memcpy(etw->u.PowerShell.ScriptBlock, contextBlock, copyLen * sizeof(WCHAR));
    etw->u.PowerShell.ScriptBlock[copyLen] = L'\0';

    return true;
}
