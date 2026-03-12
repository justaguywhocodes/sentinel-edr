/*
 * sentinel-hook/hooks_common.h
 * Shared helpers for hook detour functions.
 *
 * Provides:
 *   - Target PID resolution from process handle
 *   - Calling module lookup from return address (loader-lock-safe)
 *   - Hook event emission (ring buffer → named pipe via pipe_client)
 *   - Per-thread reentrancy guard (manual TLS)
 *   - Stack hash computation (disabled — deadlocks under loader lock)
 */

#ifndef SENTINEL_HOOKS_COMMON_H
#define SENTINEL_HOOKS_COMMON_H

#include <windows.h>
#include "telemetry.h"

/*
 * SentinelGetTargetPid
 *   Resolve a process handle to a PID. Returns 0 if the handle refers
 *   to the current process (or on failure).
 */
ULONG SentinelGetTargetPid(HANDLE ProcessHandle);

/*
 * SentinelGetCallingModule
 *   Given a return address, resolve the allocation base of the module
 *   that contains it via VirtualQuery. Writes hex address into buf.
 *   Loader-lock-safe (no PEB module list walking).
 */
void SentinelGetCallingModule(
    ULONG_PTR   ReturnAddress,
    WCHAR      *buf,
    DWORD       bufLen
);

/*
 * SentinelEmitHookEvent
 *   Push a hook event into the pipe client ring buffer.
 *   The background worker thread serializes and sends to the agent.
 */
void SentinelEmitHookEvent(SENTINEL_HOOK_EVENT *evt);

/*
 * SentinelHookFunctionName
 *   Return a human-readable name for a SENTINEL_HOOK_FUNCTION enum value.
 */
const char *SentinelHookFunctionName(SENTINEL_HOOK_FUNCTION func);

/*
 * SentinelHooksSetReady / SentinelHooksAreReady
 *   Guard flag for loader-lock safety. Hooks fire during DLL load
 *   (NtMapViewOfSection, NtAllocateVirtualMemory called by the loader).
 *   Events are suppressed until DllMain(PROCESS_ATTACH) completes.
 */
void SentinelHooksSetReady(void);
BOOL SentinelHooksAreReady(void);

/*
 * SentinelTlsInit / SentinelTlsCleanup
 *   Allocate/free the manual TLS index used by the reentrancy guard.
 *   Call from DllMain PROCESS_ATTACH / PROCESS_DETACH.
 */
void SentinelTlsInit(void);
void SentinelTlsCleanup(void);

/*
 * SentinelCaptureStackHash
 *   Compute a hash of the current call stack for behavioral correlation.
 *
 *   CURRENTLY DISABLED: RtlCaptureStackBackTrace deadlocks under loader
 *   lock (RtlVirtualUnwind acquires SRW lock for .pdata function tables).
 *   Returns 0 until loader-lock detection is added or deferred to agent.
 */
ULONG SentinelCaptureStackHash(void);

/*
 * SentinelEnterHook / SentinelLeaveHook
 *   Per-thread reentrancy guard. Prevents infinite recursion when
 *   hook capture code internally calls hooked ntdll functions.
 *
 *   Usage in every detour:
 *     NTSTATUS status = Original_Nt...(args);
 *     if (SentinelEnterHook()) {
 *         // ... capture event ...
 *         SentinelLeaveHook();
 *     }
 *     return status;
 */
BOOL SentinelEnterHook(void);
void SentinelLeaveHook(void);

/* ── Per-file hook installers ─────────────────────────────────────────────── */

void InstallMemoryHooks(void);
void InstallThreadHooks(void);
void InstallSectionHooks(void);
void InstallProcessHooks(void);
void InstallPipeHooks(void);

#endif /* SENTINEL_HOOKS_COMMON_H */
