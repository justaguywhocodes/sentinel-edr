/*
 * akesoedr-hook/hooks_thread.c
 * Detour functions for thread/APC-related ntdll hooks (Ch. 2).
 *
 * Hooks:
 *   NtCreateThreadEx   — remote thread creation (classic injection vector)
 *   NtQueueApcThread   — APC injection (early-bird, atom bombing, etc.)
 *   NtSuspendThread    — thread suspension (process hollowing prerequisite)
 *   NtResumeThread     — thread resumption (completes process hollowing)
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"
#include "evasion_detect.h"

/* ── Ntdll typedefs ───────────────────────────────────────────────────────── */

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE         ThreadHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           StartRoutine,
    PVOID           Argument,
    ULONG           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    PVOID           AttributeList
);

typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(
    HANDLE          ThreadHandle,
    PVOID           ApcRoutine,
    PVOID           ApcArgument1,
    PVOID           ApcArgument2,
    PVOID           ApcArgument3
);

typedef NTSTATUS (NTAPI *NtSuspendThread_t)(
    HANDLE          ThreadHandle,
    PULONG          PreviousSuspendCount
);

typedef NTSTATUS (NTAPI *NtResumeThread_t)(
    HANDLE          ThreadHandle,
    PULONG          PreviousSuspendCount
);

/* ── Trampoline pointers ──────────────────────────────────────────────────── */

static NtCreateThreadEx_t   Original_NtCreateThreadEx   = NULL;
static NtQueueApcThread_t   Original_NtQueueApcThread   = NULL;
static NtSuspendThread_t    Original_NtSuspendThread    = NULL;
static NtResumeThread_t     Original_NtResumeThread     = NULL;

/* ── Detour: NtCreateThreadEx ─────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtCreateThreadEx(
    PHANDLE         ThreadHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    HANDLE          ProcessHandle,
    PVOID           StartRoutine,
    PVOID           Argument,
    ULONG           CreateFlags,
    SIZE_T          ZeroBits,
    SIZE_T          StackSize,
    SIZE_T          MaximumStackSize,
    PVOID           AttributeList)
{
    NTSTATUS status;
    __try {
        status = Original_NtCreateThreadEx(
            ThreadHandle, DesiredAccess, ObjectAttributes,
            ProcessHandle, StartRoutine, Argument,
            CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtCreateThreadEx;
        evt.TargetProcessId = AkesoEDRGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)StartRoutine;
        evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
        evt.ReturnStatus    = status;
        evt.StackHash       = AkesoEDRCaptureStackHash();
        evt.EvasionFlags    = 0;
        if (!AkesoEDRCheckReturnAddress(evt.ReturnAddress))
            evt.EvasionFlags |= AKESOEDR_EVASION_DIRECT_SYSCALL;

        AkesoEDRGetCallingModule(evt.ReturnAddress,
                                 evt.CallingModule, AKESOEDR_MAX_MODULE_NAME);
        AkesoEDREmitHookEvent(&evt);
        AkesoEDRLeaveHook();
    }

    return status;
}

/* ── Detour: NtQueueApcThread ─────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtQueueApcThread(
    HANDLE          ThreadHandle,
    PVOID           ApcRoutine,
    PVOID           ApcArgument1,
    PVOID           ApcArgument2,
    PVOID           ApcArgument3)
{
    NTSTATUS status;
    __try {
        status = Original_NtQueueApcThread(
            ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtQueueApcThread;
        evt.BaseAddress     = (ULONG_PTR)ApcRoutine;
        evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
        evt.ReturnStatus    = status;
        evt.StackHash       = AkesoEDRCaptureStackHash();
        evt.EvasionFlags    = 0;
        if (!AkesoEDRCheckReturnAddress(evt.ReturnAddress))
            evt.EvasionFlags |= AKESOEDR_EVASION_DIRECT_SYSCALL;

        AkesoEDRGetCallingModule(evt.ReturnAddress,
                                 evt.CallingModule, AKESOEDR_MAX_MODULE_NAME);
        AkesoEDREmitHookEvent(&evt);
        AkesoEDRLeaveHook();
    }

    return status;
}

/* ── Detour: NtSuspendThread ──────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtSuspendThread(
    HANDLE          ThreadHandle,
    PULONG          PreviousSuspendCount)
{
    NTSTATUS status;
    __try {
        status = Original_NtSuspendThread(ThreadHandle, PreviousSuspendCount);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtSuspendThread;
        evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
        evt.ReturnStatus    = status;
        evt.StackHash       = AkesoEDRCaptureStackHash();
        evt.EvasionFlags    = 0;
        if (!AkesoEDRCheckReturnAddress(evt.ReturnAddress))
            evt.EvasionFlags |= AKESOEDR_EVASION_DIRECT_SYSCALL;

        AkesoEDRGetCallingModule(evt.ReturnAddress,
                                 evt.CallingModule, AKESOEDR_MAX_MODULE_NAME);
        AkesoEDREmitHookEvent(&evt);
        AkesoEDRLeaveHook();
    }

    return status;
}

/* ── Detour: NtResumeThread ───────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtResumeThread(
    HANDLE          ThreadHandle,
    PULONG          PreviousSuspendCount)
{
    NTSTATUS status;
    __try {
        status = Original_NtResumeThread(ThreadHandle, PreviousSuspendCount);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtResumeThread;
        evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
        evt.ReturnStatus    = status;
        evt.StackHash       = AkesoEDRCaptureStackHash();
        evt.EvasionFlags    = 0;
        if (!AkesoEDRCheckReturnAddress(evt.ReturnAddress))
            evt.EvasionFlags |= AKESOEDR_EVASION_DIRECT_SYSCALL;

        AkesoEDRGetCallingModule(evt.ReturnAddress,
                                 evt.CallingModule, AKESOEDR_MAX_MODULE_NAME);
        AkesoEDREmitHookEvent(&evt);
        AkesoEDRLeaveHook();
    }

    return status;
}

/* ── Install all thread hooks ─────────────────────────────────────────────── */

void
InstallThreadHooks(void)
{
    InstallHook("ntdll.dll", "NtCreateThreadEx",
                (void *)Hooked_NtCreateThreadEx,
                (void **)&Original_NtCreateThreadEx);

    InstallHook("ntdll.dll", "NtQueueApcThread",
                (void *)Hooked_NtQueueApcThread,
                (void **)&Original_NtQueueApcThread);

    InstallHook("ntdll.dll", "NtSuspendThread",
                (void *)Hooked_NtSuspendThread,
                (void **)&Original_NtSuspendThread);

    InstallHook("ntdll.dll", "NtResumeThread",
                (void *)Hooked_NtResumeThread,
                (void **)&Original_NtResumeThread);
}
