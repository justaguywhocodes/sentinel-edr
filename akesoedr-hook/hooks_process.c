/*
 * akesoedr-hook/hooks_process.c
 * Detour functions for process-related ntdll hooks (Ch. 2).
 *
 * Hooks:
 *   NtOpenProcess — opening process handles (credential theft, injection prep)
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"
#include "evasion_detect.h"

/* ── Ntdll typedefs ───────────────────────────────────────────────────────── */

/*
 * CLIENT_ID contains the target process/thread IDs.
 * We define it here to avoid pulling in full ntdll headers.
 */
typedef struct _AKESOEDR_CLIENT_ID {
    HANDLE  UniqueProcess;
    HANDLE  UniqueThread;
} AKESOEDR_CLIENT_ID;

typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
    PHANDLE             ProcessHandle,
    ACCESS_MASK         DesiredAccess,
    PVOID               ObjectAttributes,       /* POBJECT_ATTRIBUTES */
    AKESOEDR_CLIENT_ID *ClientId
);

/* ── Trampoline pointers ──────────────────────────────────────────────────── */

static NtOpenProcess_t  Original_NtOpenProcess  = NULL;

/* ── Detour: NtOpenProcess ────────────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtOpenProcess(
    PHANDLE             ProcessHandle,
    ACCESS_MASK         DesiredAccess,
    PVOID               ObjectAttributes,
    AKESOEDR_CLIENT_ID *ClientId)
{
    NTSTATUS status;
    __try {
        status = Original_NtOpenProcess(
            ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (AkesoEDREnterHook()) {
        AKESOEDR_HOOK_EVENT evt = {0};
        evt.Function        = AkesoEDRHookNtOpenProcess;
        evt.Protection      = DesiredAccess;  /* Repurpose: requested access mask */

        /* Extract target PID from CLIENT_ID if provided */
        if (ClientId && ClientId->UniqueProcess) {
            ULONG targetPid = (ULONG)(ULONG_PTR)ClientId->UniqueProcess;
            if (targetPid != GetCurrentProcessId()) {
                evt.TargetProcessId = targetPid;
            }
        }

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

/* ── Install all process hooks ────────────────────────────────────────────── */

void
InstallProcessHooks(void)
{
    InstallHook("ntdll.dll", "NtOpenProcess",
                (void *)Hooked_NtOpenProcess,
                (void **)&Original_NtOpenProcess);
}
