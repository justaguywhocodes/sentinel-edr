/*
 * sentinel-agent/etw/provider_kerberos.cpp
 * Parser for Microsoft-Windows-Security-Kerberos ETW events.
 *
 * Captures Kerberos ticket request events for detecting:
 *   - Kerberoasting (mass TGS requests for service accounts)
 *   - Golden Ticket / Silver Ticket usage
 *   - Pass-the-ticket lateral movement
 *   - Ticket request failures (indication of misconfigured attacks)
 *
 * Supported event IDs:
 *   14 — TGS (Ticket Granting Service) request
 *    4 — TGT (Ticket Granting Ticket) request
 *
 * UserData layout:
 *     - TargetName  : null-terminated Unicode string (SPN or principal)
 *     - Status      : ULONG (0 = success)
 *     - TicketFlags : ULONG
 *
 * P7-T2: DNS + PowerShell + Kerberos ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#include "provider_kerberos.h"
#include <cstring>
#include <cstdio>

/* ── Kerberos event IDs ───────────────────────────────────────────────── */

#define KERB_EVENT_TGS_REQUEST  14
#define KERB_EVENT_TGT_REQUEST   4

/* ── ParseKerberosEvent ────────────────────────────────────────────────── */

bool
ParseKerberosEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent)
{
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    if (eventId != KERB_EVENT_TGS_REQUEST &&
        eventId != KERB_EVENT_TGT_REQUEST) {
        return false;
    }

    /* Need at least one WCHAR for a target name */
    if (pEvent->UserDataLength < sizeof(WCHAR)) {
        return false;
    }

    const BYTE* data    = (const BYTE*)pEvent->UserData;
    const BYTE* dataEnd = data + pEvent->UserDataLength;

    /* ── Extract TargetName (null-terminated Unicode string at offset 0) ── */

    const WCHAR* nameStart = (const WCHAR*)data;
    size_t       maxChars  = (dataEnd - data) / sizeof(WCHAR);

    size_t nameLen    = 0;
    bool   terminated = false;

    for (size_t i = 0; i < maxChars; i++) {
        if (nameStart[i] == L'\0') {
            nameLen    = i;
            terminated = true;
            break;
        }
    }

    if (!terminated) {
        return false;
    }

    /* ── Populate the SENTINEL_EVENT ─────────────────────────────────── */

    memset(outEvent, 0, sizeof(SENTINEL_EVENT));

    /* Pseudo-GUID */
    {
        LARGE_INTEGER ts;
        static volatile LONG s_kerbSeqNum = 0;
        QueryPerformanceCounter(&ts);
        outEvent->EventId.Data1 = pEvent->EventHeader.ProcessId;
        outEvent->EventId.Data2 = (USHORT)GetCurrentProcessorNumber();
        outEvent->EventId.Data3 = (USHORT)InterlockedIncrement(&s_kerbSeqNum);
        *(LONGLONG*)outEvent->EventId.Data4 = ts.QuadPart;
    }

    outEvent->Timestamp.QuadPart = pEvent->EventHeader.TimeStamp.QuadPart;
    outEvent->Source   = SentinelSourceEtw;
    outEvent->Severity = SentinelSeverityInformational;

    outEvent->ProcessCtx.ProcessId = pEvent->EventHeader.ProcessId;

    /* ETW payload */
    SENTINEL_ETW_EVENT* etw = &outEvent->Payload.Etw;
    etw->Provider  = SentinelEtwKerberos;
    etw->EventId   = pEvent->EventHeader.EventDescriptor.Id;
    etw->Level     = pEvent->EventHeader.EventDescriptor.Level;
    etw->Keyword   = pEvent->EventHeader.EventDescriptor.Keyword;
    etw->ProcessId = pEvent->EventHeader.ProcessId;
    etw->ThreadId  = pEvent->EventHeader.ThreadId;

    /* Copy TargetName (bounded by SENTINEL_MAX_PATH = 520 WCHARs) */
    size_t copyLen = nameLen;
    if (copyLen >= SENTINEL_MAX_PATH) {
        copyLen = SENTINEL_MAX_PATH - 1;
    }
    memcpy(etw->u.Kerberos.TargetName, nameStart, copyLen * sizeof(WCHAR));
    etw->u.Kerberos.TargetName[copyLen] = L'\0';

    /* ── Extract Status and TicketFlags (if present) ─────────────────── */

    const BYTE* ptr = data + (nameLen + 1) * sizeof(WCHAR);  /* past null */

    if (ptr + sizeof(ULONG) <= dataEnd) {
        etw->u.Kerberos.Status = *(const ULONG*)ptr;
        ptr += sizeof(ULONG);
    }

    if (ptr + sizeof(ULONG) <= dataEnd) {
        etw->u.Kerberos.TicketFlags = *(const ULONG*)ptr;
    }

    return true;
}
