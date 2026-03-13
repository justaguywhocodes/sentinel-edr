/*
 * sentinel-agent/etw/provider_kernelprocess.cpp
 * Parser for Microsoft-Windows-Kernel-Process ETW events.
 *
 * Captures process creation and termination events as a redundant
 * telemetry source that cross-validates against the minifilter driver's
 * PsSetCreateProcessNotifyRoutineEx callbacks. If the driver sees a
 * process create but Kernel-Process ETW doesn't (or vice versa), it
 * indicates potential evasion.
 *
 * Supported event IDs:
 *   1 — ProcessStart (process creation)
 *   2 — ProcessStop  (process termination)
 *
 * ProcessStart UserData layout:
 *     - ProcessID       : UINT32
 *     - ParentProcessID : UINT32
 *     - SessionID       : UINT32
 *     - CreateTime      : FILETIME (8 bytes)
 *     - ImageName       : null-terminated Unicode string
 *
 * ProcessStop UserData layout:
 *     - ProcessID       : UINT32
 *     - CreateTime      : FILETIME (8 bytes)
 *     - ExitTime        : FILETIME (8 bytes)
 *     - ExitCode        : UINT32
 *     - TokenElevationType : UINT32
 *     - HandleCount     : UINT32
 *     - CommitCharge    : UINT64
 *     - CommitPeak      : UINT64
 *     - ImageName       : AnsiString (null-terminated)
 *
 * P7-T3: AMSI + RPC + Kernel-Process ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#include "provider_kernelprocess.h"
#include <cstring>
#include <cstdio>

/* ── Kernel-Process event IDs ──────────────────────────────────────────── */

#define KPROC_EVENT_PROCESS_START   1
#define KPROC_EVENT_PROCESS_STOP    2

/* ── Helper: copy ANSI string to WCHAR buffer ─────────────────────────── */

static void
AnsiToWchar(const char* src, WCHAR* dst, size_t dstLen)
{
    size_t i = 0;
    while (i < dstLen - 1 && src[i] != '\0') {
        dst[i] = (WCHAR)(unsigned char)src[i];
        i++;
    }
    dst[i] = L'\0';
}

/* ── ParseKernelProcessEvent ──────────────────────────────────────────── */

bool
ParseKernelProcessEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent)
{
    USHORT eventId = pEvent->EventHeader.EventDescriptor.Id;

    if (eventId != KPROC_EVENT_PROCESS_START &&
        eventId != KPROC_EVENT_PROCESS_STOP) {
        return false;
    }

    const BYTE* data    = (const BYTE*)pEvent->UserData;
    const BYTE* dataEnd = data + pEvent->UserDataLength;

    ULONG  processId       = 0;
    ULONG  parentProcessId = 0;
    ULONG  sessionId       = 0;
    ULONG  exitCode        = 0;
    WCHAR  imageName[SENTINEL_MAX_PATH] = {};

    if (eventId == KPROC_EVENT_PROCESS_START) {
        /*
         * ProcessStart: PID(4) + PPID(4) + SessionID(4) + CreateTime(8) = 20 bytes min
         */
        if (pEvent->UserDataLength < 20) {
            return false;
        }

        const BYTE* ptr = data;

        processId = *(const ULONG*)ptr;
        ptr += sizeof(ULONG);

        parentProcessId = *(const ULONG*)ptr;
        ptr += sizeof(ULONG);

        sessionId = *(const ULONG*)ptr;
        ptr += sizeof(ULONG);

        /* Skip CreateTime (FILETIME = 8 bytes) */
        ptr += sizeof(FILETIME);

        /* ImageName: null-terminated Unicode string */
        if (ptr < dataEnd) {
            const WCHAR* nameStart = (const WCHAR*)ptr;
            size_t maxChars = (dataEnd - ptr) / sizeof(WCHAR);

            size_t nameLen = 0;
            for (size_t i = 0; i < maxChars; i++) {
                if (nameStart[i] == L'\0') {
                    nameLen = i;
                    break;
                }
                nameLen = i + 1;
            }

            size_t copyLen = nameLen;
            if (copyLen >= SENTINEL_MAX_PATH) {
                copyLen = SENTINEL_MAX_PATH - 1;
            }
            memcpy(imageName, nameStart, copyLen * sizeof(WCHAR));
            imageName[copyLen] = L'\0';
        }

    } else {
        /*
         * ProcessStop: PID(4) + CreateTime(8) + ExitTime(8) + ExitCode(4) = 24 bytes min
         * Then: TokenElevationType(4) + HandleCount(4) + CommitCharge(8) + CommitPeak(8)
         * Then: ImageName (AnsiString)
         */
        if (pEvent->UserDataLength < 24) {
            return false;
        }

        const BYTE* ptr = data;

        processId = *(const ULONG*)ptr;
        ptr += sizeof(ULONG);

        /* Skip CreateTime (8 bytes) + ExitTime (8 bytes) */
        ptr += sizeof(FILETIME) + sizeof(FILETIME);

        exitCode = *(const ULONG*)ptr;
        ptr += sizeof(ULONG);

        /* Skip TokenElevationType(4) + HandleCount(4) + CommitCharge(8) + CommitPeak(8) = 24 */
        ptr += 4 + 4 + 8 + 8;

        /* ImageName: AnsiString (null-terminated) */
        if (ptr < dataEnd) {
            const char* ansiName = (const char*)ptr;
            AnsiToWchar(ansiName, imageName, SENTINEL_MAX_PATH);
        }

        /* ProcessStop doesn't include PPID or SessionID */
        parentProcessId = 0;
        sessionId = 0;
    }

    /* ── Populate the SENTINEL_EVENT ───────────────────────────────── */

    memset(outEvent, 0, sizeof(SENTINEL_EVENT));

    /* Pseudo-GUID */
    {
        LARGE_INTEGER ts;
        static volatile LONG s_kprocSeqNum = 0;
        QueryPerformanceCounter(&ts);
        outEvent->EventId.Data1 = pEvent->EventHeader.ProcessId;
        outEvent->EventId.Data2 = (USHORT)GetCurrentProcessorNumber();
        outEvent->EventId.Data3 = (USHORT)InterlockedIncrement(&s_kprocSeqNum);
        *(LONGLONG*)outEvent->EventId.Data4 = ts.QuadPart;
    }

    outEvent->Timestamp.QuadPart = pEvent->EventHeader.TimeStamp.QuadPart;
    outEvent->Source   = SentinelSourceEtw;
    outEvent->Severity = SentinelSeverityInformational;

    outEvent->ProcessCtx.ProcessId = processId;

    /* ETW payload */
    SENTINEL_ETW_EVENT* etw = &outEvent->Payload.Etw;
    etw->Provider  = SentinelEtwKernelProc;
    etw->EventId   = pEvent->EventHeader.EventDescriptor.Id;
    etw->Level     = pEvent->EventHeader.EventDescriptor.Level;
    etw->Keyword   = pEvent->EventHeader.EventDescriptor.Keyword;
    etw->ProcessId = processId;
    etw->ThreadId  = pEvent->EventHeader.ThreadId;

    /* Kernel-Process specific fields */
    etw->u.KernelProcess.ParentProcessId = parentProcessId;
    etw->u.KernelProcess.SessionId       = sessionId;
    etw->u.KernelProcess.ExitCode        = exitCode;

    size_t imgLen = wcslen(imageName);
    if (imgLen >= SENTINEL_MAX_PATH) imgLen = SENTINEL_MAX_PATH - 1;
    memcpy(etw->u.KernelProcess.ImageName, imageName, imgLen * sizeof(WCHAR));
    etw->u.KernelProcess.ImageName[imgLen] = L'\0';

    return true;
}
