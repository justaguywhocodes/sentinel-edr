/*
 * sentinel-agent/etw/provider_rpc.cpp
 * Parser for Microsoft-Windows-RPC ETW events.
 *
 * Captures RPC call events for detecting lateral movement:
 *   - PsExec (SVCCTL interface — service creation)
 *   - WMI remote execution (IWbemServices interface)
 *   - Scheduled task creation (ITaskSchedulerService)
 *   - Remote registry access (winreg interface)
 *   - DCOM/MMC lateral movement
 *
 * Supported event IDs:
 *   5 — RpcClientCallStart (this machine initiates an RPC call)
 *   6 — RpcServerCallStart (this machine receives an RPC call)
 *
 * UserData layout:
 *     - InterfaceUuid       : GUID (16 bytes)
 *     - ProcNum             : UINT32 (procedure/opnum)
 *     - Protocol            : UINT32 (ncalrpc=1, ncacn_ip_tcp=7, ncacn_np=15)
 *     - NetworkAddress      : null-terminated Unicode (variable, skipped)
 *     - Endpoint            : null-terminated Unicode (variable, skipped)
 *     - ...additional fields skipped
 *
 * P7-T3: AMSI + RPC + Kernel-Process ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#include "provider_rpc.h"
#include <cstring>
#include <cstdio>

/* ── RPC event IDs ────────────────────────────────────────────────────── */

#define RPC_EVENT_CLIENT_CALL_START     5
#define RPC_EVENT_SERVER_CALL_START     6

/* ── ParseRpcEvent ────────────────────────────────────────────────────── */

bool
ParseRpcEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent)
{
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    /*
     * Only capture server-side RPC calls (event 6). Client-side calls
     * (event 5) are extremely noisy — Windows makes hundreds per second
     * for routine local operations. Server-side calls are the high-value
     * events: they indicate incoming RPC activity (lateral movement,
     * remote service creation, WMI exec, etc.)
     */
    if (eventId != RPC_EVENT_SERVER_CALL_START) {
        return false;
    }

    /*
     * Minimum payload: GUID (16) + ProcNum (4) + Protocol (4) = 24 bytes.
     */
    if (pEvent->UserDataLength < 24) {
        return false;
    }

    const BYTE* data    = (const BYTE*)pEvent->UserData;
    const BYTE* dataEnd = data + pEvent->UserDataLength;

    /* ── Extract InterfaceUuid (first 16 bytes) ────────────────────── */

    GUID interfaceUuid;
    memcpy(&interfaceUuid, data, sizeof(GUID));
    const BYTE* ptr = data + sizeof(GUID);

    /* ── Extract ProcNum (UINT32) ──────────────────────────────────── */

    ULONG procNum = 0;
    if (ptr + sizeof(ULONG) <= dataEnd) {
        procNum = *(const ULONG*)ptr;
        ptr += sizeof(ULONG);
    }

    /* ── Extract Protocol (UINT32) ─────────────────────────────────── */

    ULONG protocol = 0;
    if (ptr + sizeof(ULONG) <= dataEnd) {
        protocol = *(const ULONG*)ptr;
    }

    /* ── Populate the SENTINEL_EVENT ───────────────────────────────── */

    memset(outEvent, 0, sizeof(SENTINEL_EVENT));

    /* Pseudo-GUID */
    {
        LARGE_INTEGER ts;
        static volatile LONG s_rpcSeqNum = 0;
        QueryPerformanceCounter(&ts);
        outEvent->EventId.Data1 = pEvent->EventHeader.ProcessId;
        outEvent->EventId.Data2 = (USHORT)GetCurrentProcessorNumber();
        outEvent->EventId.Data3 = (USHORT)InterlockedIncrement(&s_rpcSeqNum);
        *(LONGLONG*)outEvent->EventId.Data4 = ts.QuadPart;
    }

    outEvent->Timestamp.QuadPart = pEvent->EventHeader.TimeStamp.QuadPart;
    outEvent->Source   = SentinelSourceEtw;
    outEvent->Severity = SentinelSeverityInformational;

    outEvent->ProcessCtx.ProcessId = pEvent->EventHeader.ProcessId;

    /* ETW payload */
    SENTINEL_ETW_EVENT* etw = &outEvent->Payload.Etw;
    etw->Provider  = SentinelEtwRpc;
    etw->EventId   = pEvent->EventHeader.EventDescriptor.Id;
    etw->Level     = pEvent->EventHeader.EventDescriptor.Level;
    etw->Keyword   = pEvent->EventHeader.EventDescriptor.Keyword;
    etw->ProcessId = pEvent->EventHeader.ProcessId;
    etw->ThreadId  = pEvent->EventHeader.ThreadId;

    /* RPC-specific fields */
    etw->u.Rpc.InterfaceUuid = interfaceUuid;
    etw->u.Rpc.OpNum         = procNum;
    etw->u.Rpc.Protocol      = protocol;

    return true;
}
