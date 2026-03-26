/*
 * akesoedr-hook/hooks_memory.c
 * Detour functions for memory-related ntdll hooks (Ch. 2).
 *
 * Hooks:
 *   NtAllocateVirtualMemory  — memory allocation (RWX detection)
 *   NtProtectVirtualMemory   — permission changes (RW→RX shellcode pattern)
 *   NtWriteVirtualMemory     — cross-process memory writes
 *   NtReadVirtualMemory      — cross-process memory reads (credential dumping)
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"
#include "evasion_detect.h"

/* ── Ntdll typedefs ───────────────────────────────────────────────────────── */

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtect,
    PULONG      OldProtect
);

typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToWrite,
    PSIZE_T     NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *NtReadVirtualMemory_t)(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToRead,
    PSIZE_T     NumberOfBytesRead
);

/* ── Trampoline pointers (set by InstallHook) ─────────────────────────────── */

static NtAllocateVirtualMemory_t    Original_NtAllocateVirtualMemory    = NULL;
static NtProtectVirtualMemory_t     Original_NtProtectVirtualMemory     = NULL;
static NtWriteVirtualMemory_t       Original_NtWriteVirtualMemory       = NULL;
static NtReadVirtualMemory_t        Original_NtReadVirtualMemory        = NULL;

/* ── Detour: NtAllocateVirtualMemory ──────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtAllocateVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    ULONG_PTR   ZeroBits,
    PSIZE_T     RegionSize,
    ULONG       AllocationType,
    ULONG       Protect)
{
    /* Call original first — BaseAddress and RegionSize are IN/OUT */
    NTSTATUS status;
    __try {
        status = Original_NtAllocateVirtualMemory(
            ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtAllocateVirtualMemory;
        evt.TargetProcessId = AkesoEDRGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)(BaseAddress ? *BaseAddress : 0);
        evt.RegionSize      = RegionSize ? *RegionSize : 0;
        evt.AllocationType  = AllocationType;
        evt.Protection      = Protect;
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

/* ── Detour: NtProtectVirtualMemory ───────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtProtectVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID      *BaseAddress,
    PSIZE_T     RegionSize,
    ULONG       NewProtect,
    PULONG      OldProtect)
{
    NTSTATUS status;
    __try {
        status = Original_NtProtectVirtualMemory(
            ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtProtectVirtualMemory;
        evt.TargetProcessId = AkesoEDRGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)(BaseAddress ? *BaseAddress : 0);
        evt.RegionSize      = RegionSize ? *RegionSize : 0;
        evt.Protection      = NewProtect;
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

/* ── Detour: NtWriteVirtualMemory ─────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtWriteVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToWrite,
    PSIZE_T     NumberOfBytesWritten)
{
    NTSTATUS status;
    __try {
        status = Original_NtWriteVirtualMemory(
            ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToWrite, NumberOfBytesWritten);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtWriteVirtualMemory;
        evt.TargetProcessId = AkesoEDRGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)BaseAddress;
        evt.RegionSize      = NumberOfBytesToWrite;
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

/* ── Detour: NtReadVirtualMemory ──────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtReadVirtualMemory(
    HANDLE      ProcessHandle,
    PVOID       BaseAddress,
    PVOID       Buffer,
    SIZE_T      NumberOfBytesToRead,
    PSIZE_T     NumberOfBytesRead)
{
    NTSTATUS status;
    __try {
        status = Original_NtReadVirtualMemory(
            ProcessHandle, BaseAddress, Buffer,
            NumberOfBytesToRead, NumberOfBytesRead);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtReadVirtualMemory;
        evt.TargetProcessId = AkesoEDRGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)BaseAddress;
        evt.RegionSize      = NumberOfBytesToRead;
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

/* ── Install all memory hooks ─────────────────────────────────────────────── */

void
InstallMemoryHooks(void)
{
    InstallHook("ntdll.dll", "NtAllocateVirtualMemory",
                (void *)Hooked_NtAllocateVirtualMemory,
                (void **)&Original_NtAllocateVirtualMemory);

    InstallHook("ntdll.dll", "NtProtectVirtualMemory",
                (void *)Hooked_NtProtectVirtualMemory,
                (void **)&Original_NtProtectVirtualMemory);

    InstallHook("ntdll.dll", "NtWriteVirtualMemory",
                (void *)Hooked_NtWriteVirtualMemory,
                (void **)&Original_NtWriteVirtualMemory);

    InstallHook("ntdll.dll", "NtReadVirtualMemory",
                (void *)Hooked_NtReadVirtualMemory,
                (void **)&Original_NtReadVirtualMemory);
}
