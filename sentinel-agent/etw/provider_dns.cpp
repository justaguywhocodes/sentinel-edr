/*
 * sentinel-agent/etw/provider_dns.cpp
 * Parser for Microsoft-Windows-DNS-Client ETW events.
 *
 * Captures DNS resolution events so domain names can be correlated with
 * WFP network connection telemetry. This answers the question: "what
 * domain is associated with this IP?"
 *
 * Supported event IDs:
 *   3008 — DNS query completed (includes QueryName, QueryType, QueryStatus)
 *   3020 — DNS cache lookup   (includes QueryName, QueryType)
 *
 * UserData layout (TraceLogging format, both events):
 *     - QueryName   : null-terminated Unicode string
 *     - QueryType   : USHORT (A=1, AAAA=28, CNAME=5, MX=15, etc.)
 *     - QueryStatus : ULONG (0=success) — present in 3008, absent in 3020
 *
 * P7-T2: DNS + PowerShell + Kerberos ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#include "provider_dns.h"
#include <cstring>
#include <cstdio>

/* ── DNS-Client event IDs ─────────────────────────────────────────────── */

#define DNS_EVENT_QUERY_COMPLETED   3008
#define DNS_EVENT_CACHE_LOOKUP      3020

/* ── ParseDnsEvent ─────────────────────────────────────────────────────── */

bool
ParseDnsEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent)
{
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    /* Only handle query-completed and cache-lookup events */
    if (eventId != DNS_EVENT_QUERY_COMPLETED &&
        eventId != DNS_EVENT_CACHE_LOOKUP) {
        return false;
    }

    /* Need at least one WCHAR for a query name */
    if (pEvent->UserDataLength < sizeof(WCHAR)) {
        return false;
    }

    const BYTE* data    = (const BYTE*)pEvent->UserData;
    const BYTE* dataEnd = data + pEvent->UserDataLength;

    /* ── Extract QueryName (null-terminated Unicode string at offset 0) ── */

    const WCHAR* nameStart = (const WCHAR*)data;
    size_t       maxChars  = (dataEnd - data) / sizeof(WCHAR);

    /* Scan for null terminator */
    size_t nameLen = 0;
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

    /* Pseudo-GUID for event ID (same pattern as provider_dotnet.cpp) */
    {
        LARGE_INTEGER ts;
        static volatile LONG s_dnsSeqNum = 0;
        QueryPerformanceCounter(&ts);
        outEvent->EventId.Data1 = pEvent->EventHeader.ProcessId;
        outEvent->EventId.Data2 = (USHORT)GetCurrentProcessorNumber();
        outEvent->EventId.Data3 = (USHORT)InterlockedIncrement(&s_dnsSeqNum);
        *(LONGLONG*)outEvent->EventId.Data4 = ts.QuadPart;
    }

    outEvent->Timestamp.QuadPart = pEvent->EventHeader.TimeStamp.QuadPart;
    outEvent->Source   = SentinelSourceEtw;
    outEvent->Severity = SentinelSeverityInformational;

    outEvent->ProcessCtx.ProcessId = pEvent->EventHeader.ProcessId;

    /* ETW payload */
    SENTINEL_ETW_EVENT* etw = &outEvent->Payload.Etw;
    etw->Provider  = SentinelEtwDnsClient;
    etw->EventId   = pEvent->EventHeader.EventDescriptor.Id;
    etw->Level     = pEvent->EventHeader.EventDescriptor.Level;
    etw->Keyword   = pEvent->EventHeader.EventDescriptor.Keyword;
    etw->ProcessId = pEvent->EventHeader.ProcessId;
    etw->ThreadId  = pEvent->EventHeader.ThreadId;

    /* Copy QueryName (bounded by SENTINEL_MAX_PATH = 520 WCHARs) */
    size_t copyLen = nameLen;
    if (copyLen >= SENTINEL_MAX_PATH) {
        copyLen = SENTINEL_MAX_PATH - 1;
    }
    memcpy(etw->u.Dns.QueryName, nameStart, copyLen * sizeof(WCHAR));
    etw->u.Dns.QueryName[copyLen] = L'\0';

    /* ── Extract QueryType and QueryStatus (if present) ──────────────── */

    const BYTE* ptr = data + (nameLen + 1) * sizeof(WCHAR);  /* past null */

    if (ptr + sizeof(USHORT) <= dataEnd) {
        etw->u.Dns.QueryType = *(const USHORT*)ptr;
        ptr += sizeof(USHORT);
    }

    if (ptr + sizeof(ULONG) <= dataEnd) {
        etw->u.Dns.QueryStatus = *(const ULONG*)ptr;
    }

    return true;
}
