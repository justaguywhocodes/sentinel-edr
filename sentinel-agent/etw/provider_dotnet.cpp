/*
 * sentinel-agent/etw/provider_dotnet.cpp
 * Parser for Microsoft-Windows-DotNETRuntime ETW events.
 *
 * Handles .NET assembly load events to detect .NET assembly loading.
 * This catches offensive .NET tooling (Seatbelt, SharpHound, Rubeus, etc.)
 * that the driver's image-load callback can't see because the CLR loads
 * assemblies internally without NtCreateSection.
 *
 * Supported event IDs:
 *   154 — AssemblyLoad_V1 (.NET Framework, legacy CLR)
 *   155 — AssemblyLoad_V2 (early CoreCLR)
 *   290 — AssemblyLoadStart (.NET 6+/CoreCLR, ActivityTracing keyword 0x4)
 *
 * Event 154/155 layout (MOF-based, fields sequential in UserData):
 *     - AssemblyID        : UINT64
 *     - AppDomainID       : UINT64
 *     - BindingID         : UINT64
 *     - AssemblyFlags     : UINT32
 *     - FullyQualifiedName: null-terminated Unicode string
 *
 * Event 290 layout (AssemblyLoadStart, TraceLogging on CoreCLR):
 *     - AssemblyName      : null-terminated Unicode string (first field)
 *
 * P7-T1: ETW Consumer Framework + .NET Provider.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#include "provider_dotnet.h"
#include <cstring>
#include <cstdio>

/* ── .NET Runtime event IDs ─────────────────────────────────────────────── */

#define DOTNET_EVENT_ASSEMBLY_LOAD_V1       154
#define DOTNET_EVENT_ASSEMBLY_LOAD_V2       155  /* Early CoreCLR */
#define DOTNET_EVENT_ASSEMBLY_LOAD_START    290  /* .NET 6+ / CoreCLR ActivityTracing */

/* Offset to FullyQualifiedAssemblyName in UserData for legacy events (154/155):
 *   AssemblyID(8) + AppDomainID(8) + BindingID(8) + AssemblyFlags(4) = 28
 */
#define ASSEMBLY_NAME_OFFSET_LEGACY    28

/* ── Helper: extract short name from fully-qualified assembly name ─────── */

/*
 * .NET fully-qualified names look like:
 *   "Seatbelt, Version=1.1.1.0, Culture=neutral, PublicKeyToken=null"
 *
 * We want just "Seatbelt" — everything before the first comma.
 * If no comma, use the entire string.
 */
static void
ExtractShortName(
    const WCHAR* fullyQualified,
    WCHAR*       shortName,
    size_t       shortNameLen
)
{
    size_t i = 0;

    while (i < shortNameLen - 1 && fullyQualified[i] != L'\0') {
        if (fullyQualified[i] == L',') {
            break;
        }
        shortName[i] = fullyQualified[i];
        i++;
    }
    shortName[i] = L'\0';
}

/* ── ParseDotNetEvent ───────────────────────────────────────────────────── */

bool
ParseDotNetEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent)
{
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    /* Determine which assembly load event this is */
    bool isLegacyLoad = (eventId == DOTNET_EVENT_ASSEMBLY_LOAD_V1 ||
                         eventId == DOTNET_EVENT_ASSEMBLY_LOAD_V2);
    bool isNewLoad    = (eventId == DOTNET_EVENT_ASSEMBLY_LOAD_START);

    if (!isLegacyLoad && !isNewLoad) {
        return false;
    }

    const WCHAR* fqName = nullptr;
    size_t       maxChars = 0;

    if (isLegacyLoad) {
        /* Legacy events (154/155): name starts at offset 28 */
        if (pEvent->UserDataLength < ASSEMBLY_NAME_OFFSET_LEGACY + sizeof(WCHAR)) {
            return false;
        }
        fqName   = (const WCHAR*)(
            (const BYTE*)pEvent->UserData + ASSEMBLY_NAME_OFFSET_LEGACY);
        maxChars = (pEvent->UserDataLength - ASSEMBLY_NAME_OFFSET_LEGACY) / sizeof(WCHAR);
    } else {
        /* Event 290 (AssemblyLoadStart): AssemblyName is the first field */
        if (pEvent->UserDataLength < sizeof(WCHAR)) {
            return false;
        }
        fqName   = (const WCHAR*)pEvent->UserData;
        maxChars = pEvent->UserDataLength / sizeof(WCHAR);
    }

    if (maxChars == 0) {
        return false;
    }

    /* Verify null-termination within bounds */
    bool terminated = false;
    for (size_t i = 0; i < maxChars; i++) {
        if (fqName[i] == L'\0') {
            terminated = true;
            break;
        }
    }
    if (!terminated) {
        return false;
    }

    /* ── Populate the SENTINEL_EVENT ─────────────────────────────────── */

    memset(outEvent, 0, sizeof(SENTINEL_EVENT));

    /* Pseudo-GUID for event ID (same pattern as WFP callout) */
    {
        LARGE_INTEGER ts;
        static volatile LONG s_etwSeqNum = 0;
        QueryPerformanceCounter(&ts);
        outEvent->EventId.Data1 = pEvent->EventHeader.ProcessId;
        outEvent->EventId.Data2 = (USHORT)GetCurrentProcessorNumber();
        outEvent->EventId.Data3 = (USHORT)InterlockedIncrement(&s_etwSeqNum);
        *(LONGLONG*)outEvent->EventId.Data4 = ts.QuadPart;
    }

    /* Timestamp: convert ETW FILETIME to LARGE_INTEGER */
    outEvent->Timestamp.QuadPart = pEvent->EventHeader.TimeStamp.QuadPart;

    outEvent->Source   = SentinelSourceEtw;
    outEvent->Severity = SentinelSeverityInformational;

    /* Process context (minimal — PID from ETW header) */
    outEvent->ProcessCtx.ProcessId = pEvent->EventHeader.ProcessId;

    /* ETW payload */
    SENTINEL_ETW_EVENT* etw = &outEvent->Payload.Etw;
    etw->Provider  = SentinelEtwDotNet;
    etw->EventId   = pEvent->EventHeader.EventDescriptor.Id;
    etw->Level     = pEvent->EventHeader.EventDescriptor.Level;
    etw->Keyword   = pEvent->EventHeader.EventDescriptor.Keyword;
    etw->ProcessId = pEvent->EventHeader.ProcessId;
    etw->ThreadId  = pEvent->EventHeader.ThreadId;

    /* Extract short assembly name */
    ExtractShortName(fqName, etw->u.DotNet.AssemblyName,
        SENTINEL_MAX_ASSEMBLY_NAME);

    /* ClassName is not directly available in AssemblyLoad — leave empty.
     * Will be populated by Method/Type events in future providers. */

    return true;
}
