/*
 * sentinel-hook/hooks_common.c
 * Shared helpers for hook detour functions.
 *
 * LOADER-LOCK SAFETY: Hook detours fire when NtCreateSection /
 * NtMapViewOfSection / NtUnmapViewOfSection are called by the Windows
 * loader with the loader lock held. Under loader lock the following
 * are UNSAFE and will deadlock:
 *   - user32.dll functions (wsprintfA, wsprintfW)
 *   - OutputDebugStringA (acquires DBWIN mutex)
 *   - RtlCaptureStackBackTrace (RtlVirtualUnwind acquires SRW lock
 *     for .pdata function table lookup)
 *
 * Safe under loader lock:
 *   - TEB access (TlsGetValue, TlsSetValue)
 *   - Kernel calls (VirtualQuery, GetProcessId, GetCurrentProcessId)
 *   - CRT string functions (_snprintf_s, _snwprintf_s)
 *   - WriteFile on a pre-opened handle (thin ntdll wrapper)
 *   - Per-event CreateFileA/CloseHandle is safe but too slow (use pre-opened handle)
 */

#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include "hooks_common.h"

/*
 * Guard flag: hooks fire during DLL load (NtMapViewOfSection, NtAllocateVirtualMemory
 * are called by the loader). We must not call complex APIs while the loader lock
 * is held during init. Set to TRUE once DllMain(DLL_PROCESS_ATTACH) completes.
 */
static volatile BOOL g_HooksReady = FALSE;

void SentinelHooksSetReady(void) { g_HooksReady = TRUE; }
BOOL SentinelHooksAreReady(void) { return g_HooksReady; }

/*
 * Per-thread reentrancy guard using manual TLS (TlsAlloc/TlsGetValue/TlsSetValue).
 *
 * __declspec(thread) does NOT work in dynamically loaded DLLs (LoadLibrary / KAPC
 * injection) — the implicit TLS slots aren't allocated for pre-existing threads,
 * causing an access violation (0xC0000005).
 *
 * Manual TLS via TlsAlloc works for all threads regardless of when the DLL loaded.
 * TlsGetValue/TlsSetValue are safe to call from ntdll hooks because they are
 * thin wrappers around the TEB (no allocations, no locks).
 */
static DWORD g_TlsIndex = TLS_OUT_OF_INDEXES;

void
SentinelTlsInit(void)
{
    g_TlsIndex = TlsAlloc();
}

void
SentinelTlsCleanup(void)
{
    if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
        TlsFree(g_TlsIndex);
        g_TlsIndex = TLS_OUT_OF_INDEXES;
    }
}

BOOL
SentinelEnterHook(void)
{
    if (!g_HooksReady || g_TlsIndex == TLS_OUT_OF_INDEXES) {
        return FALSE;
    }

    /* Check if we're already inside a hook on this thread */
    if (TlsGetValue(g_TlsIndex) != NULL) {
        return FALSE;   /* Reentrant call — skip */
    }

    TlsSetValue(g_TlsIndex, (LPVOID)1);
    return TRUE;
}

void
SentinelLeaveHook(void)
{
    if (g_TlsIndex != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_TlsIndex, NULL);
    }
}

/* ── Hook function name table ─────────────────────────────────────────────── */

static const char *g_HookFunctionNames[] = {
    "NtAllocateVirtualMemory",      /* 0 */
    "NtProtectVirtualMemory",       /* 1 */
    "NtWriteVirtualMemory",         /* 2 */
    "NtReadVirtualMemory",          /* 3 */
    "NtCreateThreadEx",             /* 4 */
    "NtMapViewOfSection",           /* 5 */
    "NtUnmapViewOfSection",         /* 6 */
    "NtQueueApcThread",             /* 7 */
    "NtOpenProcess",                /* 8 */
    "NtSuspendThread",              /* 9 */
    "NtResumeThread",               /* 10 */
    "NtCreateSection",              /* 11 */
};

const char *
SentinelHookFunctionName(SENTINEL_HOOK_FUNCTION func)
{
    if (func >= 0 && func < SentinelHookMax) {
        return g_HookFunctionNames[func];
    }
    return "Unknown";
}

/* ── SentinelGetTargetPid ─────────────────────────────────────────────────── */

ULONG
SentinelGetTargetPid(HANDLE ProcessHandle)
{
    /* NtCurrentProcess() == (HANDLE)-1 */
    if (ProcessHandle == (HANDLE)-1 || ProcessHandle == NULL) {
        return 0;
    }

    DWORD pid = GetProcessId(ProcessHandle);
    if (pid == GetCurrentProcessId()) {
        return 0;  /* Self */
    }
    return pid;
}

/* ── SentinelGetCallingModule ─────────────────────────────────────────────── */

/*
 * Loader-lock-safe module lookup.
 *
 * Uses VirtualQuery (kernel VAD tree query, no loader lock) to find
 * the allocation base. Formats with _snwprintf_s (CRT, no locks)
 * instead of wsprintfW (user32 — deadlocks under loader lock).
 */
void
SentinelGetCallingModule(
    ULONG_PTR   ReturnAddress,
    WCHAR      *buf,
    DWORD       bufLen)
{
    MEMORY_BASIC_INFORMATION mbi;

    if (bufLen == 0) {
        return;
    }
    buf[0] = L'\0';

    if (ReturnAddress == 0) {
        return;
    }

    if (VirtualQuery((LPCVOID)ReturnAddress, &mbi, sizeof(mbi)) == sizeof(mbi)
        && mbi.AllocationBase != NULL) {
        _snwprintf_s(buf, bufLen, _TRUNCATE, L"0x%p", mbi.AllocationBase);
    }
}

/* ── SentinelCaptureStackHash ─────────────────────────────────────────────── */

/*
 * Hash the current call stack using RtlCaptureStackBackTrace (ntdll).
 *
 * DISABLED: RtlCaptureStackBackTrace calls RtlVirtualUnwind which acquires
 * an SRW lock for .pdata function table lookup. This deadlocks when
 * NtCreateSection/NtMapViewOfSection fire under the loader lock during
 * DLL loading. Stack hash will be re-enabled in P3-T4 with a loader-lock
 * detection guard or deferred to the agent side.
 */
ULONG
SentinelCaptureStackHash(void)
{
    return 0;
}

/* ── Diagnostic file log ──────────────────────────────────────────────────── */

/*
 * Pre-opened log file handle. Opened once during SentinelLogInit(),
 * closed during SentinelLogCleanup(). Avoids CreateFileA/CloseHandle
 * per event which causes too much overhead during process startup
 * (hundreds of hook events fire during DLL loading).
 */
static HANDLE g_hLogFile = INVALID_HANDLE_VALUE;

void
SentinelLogInit(void)
{
    g_hLogFile = CreateFileA(
        "C:\\SentinelPOC\\hook_event.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
}

void
SentinelLogCleanup(void)
{
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }
}

static void
SentinelLogToFile(const char *msg)
{
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_hLogFile, msg, (DWORD)lstrlenA(msg), &written, NULL);
    }
}

/* ── SentinelEmitHookEvent ────────────────────────────────────────────────── */

/*
 * P3-T2: Log hook events to diagnostic file.
 * P3-T4 will replace this with named pipe send to the agent.
 *
 * Uses _snprintf_s (CRT) instead of wsprintfA (user32) to avoid
 * deadlock under loader lock. OutputDebugStringA also removed
 * (acquires DBWIN mutex — unsafe under loader lock).
 */
void
SentinelEmitHookEvent(SENTINEL_HOOK_EVENT *evt)
{
    char msg[512];

    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
        "SentinelHook: %s targetPid=%lu addr=0x%p size=0x%Ix "
        "prot=0x%lX alloc=0x%lX stackHash=0x%08lX status=0x%08lX\n",
        SentinelHookFunctionName(evt->Function),
        evt->TargetProcessId,
        (void *)evt->BaseAddress,
        evt->RegionSize,
        evt->Protection,
        evt->AllocationType,
        evt->StackHash,
        evt->ReturnStatus);

    SentinelLogToFile(msg);
}
