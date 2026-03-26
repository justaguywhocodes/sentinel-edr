/*
 * akesoedr-hook/hooks_section.c
 * Detour functions for section-related ntdll hooks (Ch. 2).
 *
 * Hooks:
 *   NtMapViewOfSection   — section mapping (process hollowing, DLL injection)
 *   NtUnmapViewOfSection — section unmapping (unloading mapped images)
 *   NtCreateSection       — section creation (precursor to mapping)
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"
#include "evasion_detect.h"

/* ── Ntdll typedefs ───────────────────────────────────────────────────────── */

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect
);

typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(
    HANDLE          ProcessHandle,
    PVOID           BaseAddress
);

typedef NTSTATUS (NTAPI *NtCreateSection_t)(
    PHANDLE         SectionHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,       /* POBJECT_ATTRIBUTES */
    PLARGE_INTEGER  MaximumSize,
    ULONG           SectionPageProtection,
    ULONG           AllocationAttributes,
    HANDLE          FileHandle
);

/* ── Trampoline pointers ──────────────────────────────────────────────────── */

static NtMapViewOfSection_t     Original_NtMapViewOfSection     = NULL;
static NtUnmapViewOfSection_t   Original_NtUnmapViewOfSection   = NULL;
static NtCreateSection_t        Original_NtCreateSection        = NULL;

/* ── Detour: NtMapViewOfSection ───────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID          *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    ULONG           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Win32Protect)
{
    /* Call original first — BaseAddress and ViewSize are OUT */
    NTSTATUS status;
    __try {
        status = Original_NtMapViewOfSection(
            SectionHandle, ProcessHandle, BaseAddress,
            ZeroBits, CommitSize, SectionOffset,
            ViewSize, InheritDisposition, AllocationType, Win32Protect);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtMapViewOfSection;
        evt.TargetProcessId = AkesoEDRGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)(BaseAddress ? *BaseAddress : 0);
        evt.RegionSize      = ViewSize ? *ViewSize : 0;
        evt.AllocationType  = AllocationType;
        evt.Protection      = Win32Protect;
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

/* ── Detour: NtUnmapViewOfSection ─────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtUnmapViewOfSection(
    HANDLE          ProcessHandle,
    PVOID           BaseAddress)
{
    NTSTATUS status;
    __try {
        status = Original_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtUnmapViewOfSection;
        evt.TargetProcessId = AkesoEDRGetTargetPid(ProcessHandle);
        evt.BaseAddress     = (ULONG_PTR)BaseAddress;
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

/* ── Detour: NtCreateSection ──────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtCreateSection(
    PHANDLE         SectionHandle,
    ACCESS_MASK     DesiredAccess,
    PVOID           ObjectAttributes,
    PLARGE_INTEGER  MaximumSize,
    ULONG           SectionPageProtection,
    ULONG           AllocationAttributes,
    HANDLE          FileHandle)
{
    NTSTATUS status;
    __try {
        status = Original_NtCreateSection(
            SectionHandle, DesiredAccess, ObjectAttributes,
            MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtCreateSection;
        evt.Protection      = SectionPageProtection;
        evt.AllocationType  = AllocationAttributes;
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

/* ── Install all section hooks ────────────────────────────────────────────── */

void
InstallSectionHooks(void)
{
    InstallHook("ntdll.dll", "NtMapViewOfSection",
                (void *)Hooked_NtMapViewOfSection,
                (void **)&Original_NtMapViewOfSection);

    InstallHook("ntdll.dll", "NtUnmapViewOfSection",
                (void *)Hooked_NtUnmapViewOfSection,
                (void **)&Original_NtUnmapViewOfSection);

    InstallHook("ntdll.dll", "NtCreateSection",
                (void *)Hooked_NtCreateSection,
                (void **)&Original_NtCreateSection);
}
