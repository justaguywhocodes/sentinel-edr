/*
 * sentinel-drv/minifilter_pipes.c
 * Named pipe creation monitoring.
 *
 * On modern Windows, named pipe creation uses IRP_MJ_CREATE on the
 * NPFS volume (\Device\NamedPipe\...), NOT IRP_MJ_CREATE_NAMED_PIPE.
 * We detect pipe creates in the existing PostCreate callback by
 * checking the file path, then emit SENTINEL_PIPE_EVENT telemetry.
 *
 * Pipe names are matched against known-suspicious prefixes (Cobalt
 * Strike defaults).  Suspicious matches get Medium severity; normal
 * pipes get Informational.
 *
 * IRQL: Called from post-op callback at <= APC_LEVEL.
 *
 * P5-T3: Named Pipe Monitoring.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "minifilter_pipes.h"
#include "minifilter.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"

/* ── Undocumented but stable kernel APIs ───────────────────────────────── */

NTKERNELAPI
HANDLE
PsGetProcessInheritedFromUniqueProcessId(
    _In_ PEPROCESS Process
);

/* ── NPFS path prefix ──────────────────────────────────────────────────── */

static const UNICODE_STRING g_NpfsPrefix =
    RTL_CONSTANT_STRING(L"\\Device\\NamedPipe\\");

/* ── Suspicious pipe prefixes (kernel-mode accessible) ─────────────────── */

/*
 * constants.h defines the same list under #ifndef _KERNEL_MODE.
 * We duplicate it here for kernel use.  Prefixes are matched against
 * the pipe name component (after \Device\NamedPipe).
 */
static const UNICODE_STRING g_SuspiciousPipePrefixes[] = {
    RTL_CONSTANT_STRING(L"MSSE-"),
    RTL_CONSTANT_STRING(L"msagent_"),
    RTL_CONSTANT_STRING(L"postex_"),
    RTL_CONSTANT_STRING(L"status_"),
    RTL_CONSTANT_STRING(L"mojo.5688.8052.")
};

#define SUSPICIOUS_PREFIX_COUNT \
    (sizeof(g_SuspiciousPipePrefixes) / sizeof(g_SuspiciousPipePrefixes[0]))

/* ── Forward declarations ──────────────────────────────────────────────── */

static BOOLEAN
SentinelPipeIsSuspicious(
    _In_ const UNICODE_STRING *PipeName
);

/* ── Path check ────────────────────────────────────────────────────────── */

BOOLEAN
SentinelPipeIsNamedPipePath(
    _In_ const UNICODE_STRING *FilePath
)
{
    UNICODE_STRING pathPrefix;

    if (!FilePath || FilePath->Length < g_NpfsPrefix.Length) {
        return FALSE;
    }

    /* Compare the beginning of the path against \Device\NamedPipe\ */
    pathPrefix.Buffer = FilePath->Buffer;
    pathPrefix.Length = g_NpfsPrefix.Length;
    pathPrefix.MaximumLength = g_NpfsPrefix.Length;

    return (RtlCompareUnicodeString(&pathPrefix, &g_NpfsPrefix, TRUE) == 0);
}

/* ── Emit pipe event ───────────────────────────────────────────────────── */

VOID
SentinelPipeEmitEvent(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
)
{
    SENTINEL_EVENT              *event = NULL;
    PFLT_FILE_NAME_INFORMATION   nameInfo = NULL;
    NTSTATUS                     status;

    UNREFERENCED_PARAMETER(FltObjects);

    /* Don't emit if agent isn't connected */
    if (!SentinelCommsIsConnected()) {
        return;
    }

    /* Allocate event */
    event = (SENTINEL_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SENTINEL_EVENT),
        SENTINEL_TAG_FILE
    );
    if (!event) {
        return;
    }

    RtlZeroMemory(event, sizeof(SENTINEL_EVENT));

    /* Fill envelope */
    __try {
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal */
    }

    event->Source   = SentinelSourceDriverPipe;
    event->Severity = SentinelSeverityInformational;

    /*
     * Process context — use PsLookupProcessByProcessId instead of
     * Data->Thread which may be NULL/invalid for IRP_MJ_CREATE_NAMED_PIPE.
     */
    __try {
        ULONG pid = FltGetRequestorProcessId(Data);
        PEPROCESS process = NULL;

        event->ProcessCtx.ProcessId = pid;
        event->ProcessCtx.ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

        if (NT_SUCCESS(PsLookupProcessByProcessId(UlongToHandle(pid), &process))) {
            PUNICODE_STRING imageName = NULL;

            event->ProcessCtx.ParentProcessId =
                (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(process);

            if (NT_SUCCESS(SeLocateProcessImageName(process, &imageName))) {
                if (imageName && imageName->Buffer && imageName->Length > 0) {
                    RtlStringCchCopyNW(
                        event->ProcessCtx.ImagePath,
                        SENTINEL_MAX_PATH,
                        imageName->Buffer,
                        imageName->Length / sizeof(WCHAR)
                    );
                }
                if (imageName) {
                    ExFreePool(imageName);
                }
            }

            ObDereferenceObject(process);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: Exception 0x%08X in pipe FillProcessCtx\n",
            GetExceptionCode()));
    }

    /* PID (also set above, but ensure it's always populated) */
    __try {
        event->Payload.Pipe.CreatingProcessId = FltGetRequestorProcessId(Data);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal */
    }

    /* Pipe name and suspicious check */
    __try {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );
        if (!NT_SUCCESS(status)) {
            status = FltGetFileNameInformation(
                Data,
                FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo
            );
        }

        if (NT_SUCCESS(status)) {
            /* Store full path in PipeName */
            RtlStringCchCopyNW(
                event->Payload.Pipe.PipeName,
                SENTINEL_MAX_PIPE_NAME,
                nameInfo->Name.Buffer,
                nameInfo->Name.Length / sizeof(WCHAR)
            );

            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SentinelPOC: Pipe name resolved: %wZ\n",
                &nameInfo->Name));

            /*
             * Extract the pipe name after \Device\NamedPipe\ prefix.
             * FinalComponent is unreliable on NPFS — manually strip
             * the prefix to get the bare pipe name for matching.
             */
            {
                UNICODE_STRING pipeName;
                USHORT prefixLen = g_NpfsPrefix.Length;

                if (nameInfo->Name.Length > prefixLen) {
                    pipeName.Buffer = (PWCH)((PUCHAR)nameInfo->Name.Buffer + prefixLen);
                    pipeName.Length = nameInfo->Name.Length - prefixLen;
                    pipeName.MaximumLength = pipeName.Length;
                } else {
                    /* Fallback: try FinalComponent */
                    FltParseFileNameInformation(nameInfo);
                    pipeName = nameInfo->FinalComponent;
                }

                if (SentinelPipeIsSuspicious(&pipeName)) {
                    event->Payload.Pipe.IsSuspicious = TRUE;
                    event->Severity = SentinelSeverityMedium;
                    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "SentinelPOC: SUSPICIOUS pipe detected!\n"));
                }
            }

            FltReleaseFileNameInformation(nameInfo);
            nameInfo = NULL;
        } else {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SentinelPOC: FltGetFileNameInformation failed for pipe: 0x%08X\n",
                status));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: Exception 0x%08X in pipe name query\n",
            GetExceptionCode()));
    }

    /* Access mode from create parameters */
    __try {
        event->Payload.Pipe.AccessMode =
            Data->Iopb->Parameters.Create.ShareAccess;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal */
    }

    /* Send to agent */
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "SentinelPOC: Sending pipe event src=%d pid=%lu pipe=%S\n",
        event->Source,
        event->Payload.Pipe.CreatingProcessId,
        event->Payload.Pipe.PipeName));

    SentinelCommsSend(event);

    ExFreePoolWithTag(event, SENTINEL_TAG_FILE);
}

/* ── Suspicious pipe matching ──────────────────────────────────────────── */

/*
 * Check if the pipe name starts with a known-suspicious prefix.
 * Uses case-insensitive prefix matching against the final component.
 */
static BOOLEAN
SentinelPipeIsSuspicious(
    _In_ const UNICODE_STRING *PipeName
)
{
    ULONG i;

    if (!PipeName || PipeName->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < SUSPICIOUS_PREFIX_COUNT; i++) {
        const UNICODE_STRING *prefix = &g_SuspiciousPipePrefixes[i];

        if (PipeName->Length >= prefix->Length) {
            UNICODE_STRING namePrefix;
            namePrefix.Buffer = PipeName->Buffer;
            namePrefix.Length = prefix->Length;
            namePrefix.MaximumLength = prefix->Length;

            if (RtlCompareUnicodeString(&namePrefix, prefix, TRUE) == 0) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SentinelPOC: Suspicious pipe detected: %wZ\n", PipeName));
                return TRUE;
            }
        }
    }

    return FALSE;
}

/* ── IRP_MJ_CREATE_NAMED_PIPE callbacks ───────────────────────────────── */

/*
 * Server-side pipe creation: NtCreateNamedPipeFile dispatches
 * IRP_MJ_CREATE_NAMED_PIPE.  This captures the actual pipe creation
 * (as opposed to client-side IRP_MJ_CREATE opens).
 */
FLT_PREOP_CALLBACK_STATUS
SentinelPreCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_   PVOID                       *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /*
     * Do NOT use SentinelMinifilterShouldSkipPreOp here — it filters
     * KernelMode requestors, but NtCreateNamedPipeFile may arrive with
     * RequestorMode == KernelMode even for user-mode pipe creation.
     * Only skip fast I/O and high IRQL.
     */
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "SentinelPOC: PreCreateNamedPipe hit! reqMode=%d pid=%lu\n",
        (int)Data->RequestorMode,
        FltGetRequestorProcessId(Data)));

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
SentinelPostCreateNamedPipe(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: PostCreateNamedPipe FAILED status=0x%08X\n",
            Data->IoStatus.Status));
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "SentinelPOC: PostCreateNamedPipe SUCCESS — emitting pipe event\n"));

    SentinelPipeEmitEvent(Data, FltObjects);

    return FLT_POSTOP_FINISHED_PROCESSING;
}
