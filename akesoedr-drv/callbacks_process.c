/*
 * akesoedr-drv/callbacks_process.c
 * Process creation/termination callback — PsSetCreateProcessNotifyRoutineEx.
 *
 * On every process create/terminate on the system, this callback:
 *   1. Populates a AKESOEDR_EVENT with process metadata
 *   2. Extracts token info (user SID, integrity level, elevation)
 *   3. Sends the event to the agent over the filter communication port
 *
 * IRQL: The callback runs at PASSIVE_LEVEL (guaranteed by the OS).
 *
 * Book reference: Chapter 3 — Process- and Thread-Creation Notifications.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "callbacks_process.h"
#include "self_protect.h"

/* ── Undocumented/missing kernel API declarations ─────────────────────────── */

NTKERNELAPI
HANDLE
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process
);

NTKERNELAPI
NTSTATUS
PsGetProcessSessionId(
    _In_  PEPROCESS Process,
    _Out_ PULONG    SessionId
);

/* ── Forward declarations ────────────────────────────────────────────────── */

static VOID
AkesoEDRProcessNotifyCallback(
    _Inout_  PEPROCESS              Process,
    _In_     HANDLE                 ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

static VOID
AkesoEDRFillProcessContext(
    _Out_    AKESOEDR_PROCESS_CTX*  Ctx,
    _In_     PEPROCESS              Process,
    _In_     HANDLE                 ProcessId
);

static VOID
AkesoEDRExtractTokenInfo(
    _In_     PEPROCESS              Process,
    _Out_    WCHAR*                 SidBuffer,
    _In_     ULONG                  SidBufferLen,
    _Out_    ULONG*                 IntegrityLevel,
    _Out_    BOOLEAN*               IsElevated
);

static VOID
AkesoEDRSidToString(
    _In_     PSID                   Sid,
    _Out_    WCHAR*                 Buffer,
    _In_     ULONG                  BufferLen
);

/* ── Section placement ───────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AkesoEDRProcessCallbackInit)
#pragma alloc_text(PAGE, AkesoEDRProcessCallbackStop)
#endif

/* ── State ───────────────────────────────────────────────────────────────── */

static BOOLEAN g_ProcessCallbackRegistered = FALSE;

/* ── Public API ──────────────────────────────────────────────────────────── */

NTSTATUS
AkesoEDRProcessCallbackInit(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_ProcessCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    status = PsSetCreateProcessNotifyRoutineEx(
        AkesoEDRProcessNotifyCallback,
        FALSE   /* Remove = FALSE → register */
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: PsSetCreateProcessNotifyRoutineEx failed 0x%08X\n", status));
        return status;
    }

    g_ProcessCallbackRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Process creation callback registered\n"));

    return STATUS_SUCCESS;
}

VOID
AkesoEDRProcessCallbackStop(VOID)
{
    PAGED_CODE();

    if (!g_ProcessCallbackRegistered) {
        return;
    }

    PsSetCreateProcessNotifyRoutineEx(
        AkesoEDRProcessNotifyCallback,
        TRUE    /* Remove = TRUE → unregister */
    );

    g_ProcessCallbackRegistered = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Process creation callback unregistered\n"));
}

/* ── Callback implementation ─────────────────────────────────────────────── */

/*
 * PsSetCreateProcessNotifyRoutineEx callback.
 *
 * CreateInfo != NULL → process is being created
 * CreateInfo == NULL → process is terminating
 */
static VOID
AkesoEDRProcessNotifyCallback(
    _Inout_  PEPROCESS              Process,
    _In_     HANDLE                 ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    AKESOEDR_EVENT *event;

    /* P11-T3: Canary counter for self-protection monitoring */
    AkesoEDRCanaryProcessCallback();

    /*
     * AKESOEDR_EVENT is ~22 KB — far too large for the kernel stack
     * (default 12-24 KB).  Pool-allocate to avoid stack overflow BSOD.
     */
    event = (AKESOEDR_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AKESOEDR_EVENT), AKESOEDR_TAG_EVENT);
    if (!event) {
        return;
    }

    /*
     * Wrap in __try/__except: certain edge-case processes (System, Idle,
     * processes being torn down) can cause access violations in token
     * queries or EPROCESS field access.  A crash here = instant BSOD.
     */
    __try {

        /* Initialize event envelope */
        RtlZeroMemory(event, sizeof(AKESOEDR_EVENT));
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
        event->Source   = AkesoEDRSourceDriverProcess;
        event->Severity = AkesoEDRSeverityInformational;

        /* Fill process context (who generated the event) */
        AkesoEDRFillProcessContext(&event->ProcessCtx, Process, ProcessId);

        if (CreateInfo != NULL) {
            /* ── Process creation ─────────────────────────────────────── */

            event->Payload.Process.IsCreate      = TRUE;
            event->Payload.Process.NewProcessId  = (ULONG)(ULONG_PTR)ProcessId;
            event->Payload.Process.ParentProcessId = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
            event->Payload.Process.CreatingThreadId = (ULONG)(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread;

            /* Image path from CreateInfo->ImageFileName */
            if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Length > 0) {
                RtlStringCchCopyNW(
                    event->Payload.Process.ImagePath,
                    AKESOEDR_MAX_PATH,
                    CreateInfo->ImageFileName->Buffer,
                    CreateInfo->ImageFileName->Length / sizeof(WCHAR)
                );
            }

            /* Command line from CreateInfo->CommandLine */
            if (CreateInfo->CommandLine && CreateInfo->CommandLine->Length > 0) {
                RtlStringCchCopyNW(
                    event->Payload.Process.CommandLine,
                    AKESOEDR_MAX_CMDLINE,
                    CreateInfo->CommandLine->Buffer,
                    CreateInfo->CommandLine->Length / sizeof(WCHAR)
                );
            }

            /* Token info: user SID, integrity level, elevation */
            AkesoEDRExtractTokenInfo(
                Process,
                event->Payload.Process.UserSid,
                AKESOEDR_MAX_SID_STRING,
                &event->Payload.Process.IntegrityLevel,
                &event->Payload.Process.IsElevated
            );

            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "AkesoEDR: Process CREATE PID=%lu PPID=%lu\n",
                (ULONG)(ULONG_PTR)ProcessId,
                (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId));

        } else {
            /* ── Process termination ──────────────────────────────────── */

            event->Payload.Process.IsCreate      = FALSE;
            event->Payload.Process.NewProcessId  = (ULONG)(ULONG_PTR)ProcessId;

            /* Exit status is not reliably available in the callback */
            event->Payload.Process.ExitStatus = 0;

            /* Still fill the parent PID from the EPROCESS */
            {
                HANDLE parentPid = PsGetProcessInheritedFromUniqueProcessId(Process);
                event->Payload.Process.ParentProcessId = (ULONG)(ULONG_PTR)parentPid;
            }

            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "AkesoEDR: Process EXIT PID=%lu\n",
                (ULONG)(ULONG_PTR)ProcessId));
        }

        /* Send event to agent (silently drops if no agent connected) */
        AkesoEDRCommsSend(event);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: Exception 0x%08X in process callback PID=%lu\n",
            GetExceptionCode(), (ULONG)(ULONG_PTR)ProcessId));
    }

    ExFreePoolWithTag(event, AKESOEDR_TAG_EVENT);
}

/* ── Helper: fill process context ─────────────────────────────────────────── */

static VOID
AkesoEDRFillProcessContext(
    _Out_    AKESOEDR_PROCESS_CTX*  Ctx,
    _In_     PEPROCESS              Process,
    _In_     HANDLE                 ProcessId
)
{
    PUNICODE_STRING imageName = NULL;

    Ctx->ProcessId       = (ULONG)(ULONG_PTR)ProcessId;
    Ctx->ParentProcessId = (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(Process);
    Ctx->ThreadId        = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    {
        ULONG sessionId = 0;
        NTSTATUS sessionStatus = PsGetProcessSessionId(Process, &sessionId);
        Ctx->SessionId = NT_SUCCESS(sessionStatus) ? sessionId : 0;
    }

    KeQuerySystemTimePrecise(&Ctx->ProcessCreateTime);

    /* Get the image file name */
    if (NT_SUCCESS(SeLocateProcessImageName(Process, &imageName))) {
        if (imageName && imageName->Buffer && imageName->Length > 0) {
            RtlStringCchCopyNW(
                Ctx->ImagePath,
                AKESOEDR_MAX_PATH,
                imageName->Buffer,
                imageName->Length / sizeof(WCHAR)
            );
        }
        if (imageName) {
            ExFreePool(imageName);
        }
    }

    /* Token info for the process context */
    AkesoEDRExtractTokenInfo(
        Process,
        Ctx->UserSid,
        AKESOEDR_MAX_SID_STRING,
        &Ctx->IntegrityLevel,
        &Ctx->IsElevated
    );
}

/* ── Helper: extract token info ───────────────────────────────────────────── */

/*
 * Opens the process token and extracts:
 *   - User SID (converted to string)
 *   - Integrity level (SECURITY_MANDATORY_*_RID)
 *   - Whether the token is elevated
 */
static VOID
AkesoEDRExtractTokenInfo(
    _In_     PEPROCESS              Process,
    _Out_    WCHAR*                 SidBuffer,
    _In_     ULONG                  SidBufferLen,
    _Out_    ULONG*                 IntegrityLevel,
    _Out_    BOOLEAN*               IsElevated
)
{
    NTSTATUS            status;
    PACCESS_TOKEN       token = NULL;
    PTOKEN_USER         tokenUser = NULL;

    /* Defaults */
    SidBuffer[0] = L'\0';
    *IntegrityLevel = 0;
    *IsElevated = FALSE;

    /* Reference the process token */
    token = PsReferencePrimaryToken(Process);
    if (!token) {
        return;
    }

    /* ── User SID ─────────────────────────────────────────────────────── */

    status = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
    if (NT_SUCCESS(status) && tokenUser) {
        AkesoEDRSidToString(
            tokenUser->User.Sid,
            SidBuffer,
            SidBufferLen
        );
        ExFreePool(tokenUser);
    }

    /* ── Integrity level ──────────────────────────────────────────────── */

    {
        PTOKEN_MANDATORY_LABEL label = NULL;

        status = SeQueryInformationToken(
            token, TokenIntegrityLevel, (PVOID*)&label
        );

        if (NT_SUCCESS(status) && label) {
            PSID sid = label->Label.Sid;
            if (sid && RtlValidSid(sid)) {
                ULONG subAuthCount = *RtlSubAuthorityCountSid(sid);
                if (subAuthCount > 0) {
                    *IntegrityLevel = *RtlSubAuthoritySid(sid, subAuthCount - 1);
                }
            }
            ExFreePool(label);
        }
    }

    /* ── Elevation ────────────────────────────────────────────────────── */

    {
        PTOKEN_ELEVATION pElevation = NULL;

        status = SeQueryInformationToken(
            token, TokenElevation, (PVOID*)&pElevation
        );

        if (NT_SUCCESS(status) && pElevation) {
            *IsElevated = (pElevation->TokenIsElevated != 0);
            ExFreePool(pElevation);
        }
    }

    PsDereferencePrimaryToken(token);
}

/* ── Helper: SID to string ────────────────────────────────────────────────── */

/*
 * Convert a SID to its string representation (S-1-5-21-...).
 * We build it manually since RtlConvertSidToUnicodeString allocates
 * and we want to write directly into a fixed buffer.
 */
static VOID
AkesoEDRSidToString(
    _In_     PSID                   Sid,
    _Out_    WCHAR*                 Buffer,
    _In_     ULONG                  BufferLen
)
{
    UNICODE_STRING sidString = { 0 };
    NTSTATUS status;

    Buffer[0] = L'\0';

    status = RtlConvertSidToUnicodeString(&sidString, Sid, TRUE);
    if (NT_SUCCESS(status)) {
        RtlStringCchCopyNW(
            Buffer,
            BufferLen,
            sidString.Buffer,
            sidString.Length / sizeof(WCHAR)
        );
        RtlFreeUnicodeString(&sidString);
    }
}
