/*
 * akesoedr-drv/minifilter.c
 * Filesystem minifilter I/O callback implementation.
 *
 * Monitors file create, write, rename, and delete operations.
 * Excluded paths (Windows, Program Files) are filtered in pre-op
 * to avoid event floods.  Post-op emits telemetry only after
 * the I/O completes successfully.
 *
 * IRQL:
 *   - IRP_MJ_CREATE / IRP_MJ_SET_INFORMATION: PASSIVE_LEVEL
 *   - IRP_MJ_WRITE: <= APC_LEVEL (paging I/O filtered out in pre-op)
 *   - FltGetFileNameInformation: requires <= APC_LEVEL
 *   - AkesoEDRCommsSend (FltSendMessage): requires <= APC_LEVEL
 *
 * P5-T1: Minifilter Registration & I/O Callbacks.
 * Book reference: Chapter 6 — Filesystem Minifilter Drivers.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "minifilter.h"
#include "minifilter_pipes.h"
#include "file_hash.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "self_protect.h"

/* ── Undocumented but stable kernel APIs ───────────────────────────────── */

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

/* ── Path exclusion list ──────────────────────────────────────────────── */

/*
 * Paths containing these substrings (case-insensitive) are excluded
 * from monitoring to reduce noise.  Matches constants.h definitions
 * for user-mode but defined here for kernel-mode use.
 */
static const WCHAR* g_FsExclusions[] = {
    L"\\Windows\\",
    L"\\Program Files\\",
    L"\\Program Files (x86)\\"
};

#define FS_EXCLUSION_COUNT (sizeof(g_FsExclusions) / sizeof(g_FsExclusions[0]))

/* ── Forward declarations ─────────────────────────────────────────────── */

static BOOLEAN
AkesoEDRMinifilterIsExcluded(
    _In_ PFLT_CALLBACK_DATA Data
);

/* Non-static — also called from minifilter_pipes.c */
BOOLEAN
AkesoEDRMinifilterShouldSkipPreOp(
    _In_ PFLT_CALLBACK_DATA Data
);

/* Non-static — also called from file_hash.c */
void
AkesoEDRMinifilterFillProcessCtx(
    _Out_ AKESOEDR_PROCESS_CTX *Ctx,
    _In_  PFLT_CALLBACK_DATA    Data
);

void
AkesoEDRMinifilterEmitFileEvent(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ AKESOEDR_FILE_OP      Operation
);

static void
AkesoEDRExtractTokenInfoMf(
    _In_  PEPROCESS Process,
    _Out_ WCHAR    *SidBuffer,
    _In_  ULONG     SidBufferLen,
    _Out_ ULONG    *IntegrityLevel,
    _Out_ BOOLEAN  *IsElevated
);

static void
AkesoEDRSidToStringMf(
    _In_  PSID    Sid,
    _Out_ WCHAR  *Buffer,
    _In_  ULONG   BufferLen
);

/* ── Case-insensitive substring search ────────────────────────────────── */

/*
 * Searches for needle in haystack (case-insensitive, WCHAR).
 * Returns TRUE if found.
 */
static BOOLEAN
WcsCaseContains(
    _In_ const WCHAR *Haystack,
    _In_ ULONG        HaystackLen,    /* in WCHARs */
    _In_ const WCHAR *Needle
)
{
    ULONG needleLen = 0;
    const WCHAR *p;

    while (Needle[needleLen] != L'\0') {
        needleLen++;
    }

    if (needleLen == 0 || needleLen > HaystackLen) {
        return FALSE;
    }

    for (p = Haystack; p <= Haystack + HaystackLen - needleLen; p++) {
        ULONG i;
        BOOLEAN match = TRUE;
        for (i = 0; i < needleLen; i++) {
            WCHAR h = p[i];
            WCHAR n = Needle[i];
            /* Simple ASCII case fold */
            if (h >= L'A' && h <= L'Z') h += 32;
            if (n >= L'A' && n <= L'Z') n += 32;
            if (h != n) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }

    return FALSE;
}

/* ── AkesoEDRMinifilterShouldSkipPreOp ────────────────────────────────── */

/*
 * Common pre-op filtering: skip fast I/O, kernel callers, paging I/O.
 * Non-static — also used by minifilter_pipes.c.
 */
BOOLEAN
AkesoEDRMinifilterShouldSkipPreOp(
    _In_ PFLT_CALLBACK_DATA Data
)
{
    /* Skip fast I/O operations — unsafe for name queries */
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        return TRUE;
    }

    /* Skip kernel-mode requestors — FltGetFileNameInformation is unsafe
     * in kernel-mode I/O contexts (elevated IRQL, locks held).
     * User-mode file ops (CreateFile, WriteFile, etc.) always have
     * RequestorMode == UserMode so they still flow through. */
    if (Data->RequestorMode == KernelMode) {
        return TRUE;
    }

    /* Skip paging I/O — these are cache manager / memory manager operations */
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return TRUE;
    }

    /* Safety: FltGetFileNameInformation requires <= APC_LEVEL */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return TRUE;
    }

    return FALSE;
}

/* ── AkesoEDRMinifilterIsExcluded ─────────────────────────────────────── */

/*
 * Check whether the file path is in the exclusion list.
 * Returns TRUE if the path should be excluded (no event emitted).
 */
static BOOLEAN
AkesoEDRMinifilterIsExcluded(
    _In_ PFLT_CALLBACK_DATA Data
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    BOOLEAN  excluded = FALSE;
    ULONG    i;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        /* Normalized may fail; try opened name */
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo
        );
    }

    if (!NT_SUCCESS(status)) {
        /* Can't get the name — don't exclude, but also don't crash */
        return FALSE;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FALSE;
    }

    /* Check each exclusion pattern against the normalized name */
    for (i = 0; i < FS_EXCLUSION_COUNT; i++) {
        if (WcsCaseContains(
                nameInfo->Name.Buffer,
                nameInfo->Name.Length / sizeof(WCHAR),
                g_FsExclusions[i])) {
            excluded = TRUE;
            break;
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return excluded;
}

/* ── IRP_MJ_CREATE callbacks ──────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
AkesoEDRPreCreate(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    AkesoEDRCanaryMinifilterCallback();

    if (AkesoEDRMinifilterShouldSkipPreOp(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Skip directory opens — they generate massive noise */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Skip if path is excluded (wrapped in __try — FltGetFileNameInformation
     * can fault in edge cases; if it does, let the event through) */
    __try {
        if (AkesoEDRMinifilterIsExcluded(Data)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Fall through — emit event rather than silently swallowing it */
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
AkesoEDRPostCreate(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
)
{
    ULONG_PTR info;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Don't process during volume teardown */
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Only emit events for successful operations */
    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /*
     * Only emit for creates that actually opened/created a file.
     * FILE_OPENED = existing file opened, FILE_CREATED = new file created,
     * FILE_OVERWRITTEN = existing file overwritten.
     */
    info = Data->IoStatus.Information;
    if (info != FILE_CREATED &&
        info != FILE_OPENED &&
        info != FILE_OVERWRITTEN &&
        info != FILE_SUPERSEDED) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /*
     * Check if this is a named pipe creation on the NPFS volume
     * (\Device\NamedPipe\...).  If so, emit a pipe event instead
     * of a file event — the payloads use different union members.
     */
    __try {
        PFLT_FILE_NAME_INFORMATION pipeNameInfo = NULL;
        NTSTATUS pipeStatus;

        pipeStatus = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &pipeNameInfo
        );
        if (!NT_SUCCESS(pipeStatus)) {
            pipeStatus = FltGetFileNameInformation(
                Data,
                FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                &pipeNameInfo
            );
        }
        if (NT_SUCCESS(pipeStatus)) {
            BOOLEAN isPipe = AkesoEDRPipeIsNamedPipePath(&pipeNameInfo->Name);

            if (isPipe) {
                KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "AkesoEDR: PostCreate detected pipe path: %wZ\n",
                    &pipeNameInfo->Name));
            }

            FltReleaseFileNameInformation(pipeNameInfo);

            if (isPipe) {
                AkesoEDRPipeEmitEvent(Data, FltObjects);
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal — fall through to file event */
    }

    /*
     * Content-modifying creates get async hash + event.
     * Read-only opens (FILE_OPENED) get synchronous event without hash.
     */
    if (info == FILE_CREATED ||
        info == FILE_OVERWRITTEN ||
        info == FILE_SUPERSEDED) {
        AkesoEDRFileHashQueueWorkItem(Data, FltObjects, AkesoEDRFileOpCreate);
    } else {
        AkesoEDRMinifilterEmitFileEvent(Data, FltObjects, AkesoEDRFileOpCreate);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ── IRP_MJ_WRITE callbacks ───────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
AkesoEDRPreWrite(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (AkesoEDRMinifilterShouldSkipPreOp(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        if (AkesoEDRMinifilterIsExcluded(Data)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Fall through */
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
AkesoEDRPostWrite(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    AkesoEDRMinifilterEmitFileEvent(Data, FltObjects, AkesoEDRFileOpWrite);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ── IRP_MJ_SET_INFORMATION callbacks ─────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
AkesoEDRPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
)
{
    FILE_INFORMATION_CLASS infoClass;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    /*
     * Don't use AkesoEDRMinifilterShouldSkipPreOp here — it filters
     * KernelMode requestors, but NTFS can issue FileDispositionInformation
     * at KernelMode even for user-mode deletes.  We still skip fast I/O
     * and paging I/O for safety.
     */
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /*
     * Only monitor rename and delete operations.
     * Other SetInformation classes (timestamps, attributes, etc.) are noise.
     */
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx &&
        infoClass != FileDispositionInformation &&
        infoClass != FileDispositionInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        if (AkesoEDRMinifilterIsExcluded(Data)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Fall through */
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
AkesoEDRPostSetInfo(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
)
{
    FILE_INFORMATION_CLASS infoClass;
    AKESOEDR_FILE_OP op;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Determine sub-operation */
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx) {
        op = AkesoEDRFileOpRename;
    } else if (infoClass == FileDispositionInformation ||
               infoClass == FileDispositionInformationEx) {
        op = AkesoEDRFileOpDelete;
    } else {
        op = AkesoEDRFileOpSetInfo;
    }

    AkesoEDRMinifilterEmitFileEvent(Data, FltObjects, op);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ── Event emission helper ────────────────────────────────────────────── */

/*
 * Pool-allocate a AKESOEDR_EVENT, fill it with file operation details,
 * and send it to the agent via the filter communication port.
 *
 * Each risky operation is isolated in its own __try/__except block so
 * a crash in one (e.g., name query or token extraction) degrades
 * gracefully — the event is still sent with whatever fields succeeded.
 */
void
AkesoEDRMinifilterEmitFileEvent(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ AKESOEDR_FILE_OP      Operation
)
{
    AKESOEDR_EVENT *event;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    /* Don't send if agent isn't connected */
    if (!AkesoEDRCommsIsConnected()) {
        return;
    }

    /*
     * IRQL guard: Post-operation callbacks (especially IRP_MJ_WRITE) can
     * run at DISPATCH_LEVEL when I/O completes asynchronously via DPC.
     * Most APIs we call below (FltGetFileNameInformation, FltQueryInformationFile,
     * SeLocateProcessImageName, SeQueryInformationToken) require <= APC_LEVEL.
     * Bail out rather than risk a BSOD.
     */
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    /*
     * AKESOEDR_EVENT is ~22 KB — too large for kernel stack.
     * Pool-allocate to avoid stack overflow BSOD.
     */
    event = (AKESOEDR_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(AKESOEDR_EVENT),
        AKESOEDR_TAG_FILE
    );

    if (!event) {
        return;
    }

    /* Initialize event envelope — safe fields first */
    RtlZeroMemory(event, sizeof(AKESOEDR_EVENT));
    event->Source = AkesoEDRSourceDriverMinifilter;
    event->Severity = AkesoEDRSeverityInformational;
    event->Payload.File.Operation = Operation;
    event->Payload.File.RequestingProcessId =
        FltGetRequestorProcessId(Data);

    /* UUID + timestamp */
    __try {
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: Exception 0x%08X in UUID/timestamp\n",
            GetExceptionCode()));
    }

    /* Process context */
    __try {
        AkesoEDRMinifilterFillProcessCtx(&event->ProcessCtx, Data);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: Exception 0x%08X in FillProcessCtx\n",
            GetExceptionCode()));
    }

    /* File path query */
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
            FltParseFileNameInformation(nameInfo);

            RtlStringCchCopyNW(
                event->Payload.File.FilePath,
                AKESOEDR_MAX_PATH,
                nameInfo->Name.Buffer,
                nameInfo->Name.Length / sizeof(WCHAR)
            );

            FltReleaseFileNameInformation(nameInfo);
            nameInfo = NULL;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: Exception 0x%08X in file name query\n",
            GetExceptionCode()));
    }

    /* File size */
    __try {
        FILE_STANDARD_INFORMATION stdInfo = { 0 };
        status = FltQueryInformationFile(
            FltObjects->Instance,
            Data->Iopb->TargetFileObject,
            &stdInfo,
            sizeof(stdInfo),
            FileStandardInformation,
            NULL
        );
        if (NT_SUCCESS(status)) {
            event->Payload.File.FileSize = stdInfo.EndOfFile;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal — size stays 0 */
    }

    /* Rename: extract new file path */
    if (Operation == AkesoEDRFileOpRename) {
        __try {
            PFILE_RENAME_INFORMATION renameInfo =
                (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters
                    .SetFileInformation.InfoBuffer;

            if (renameInfo && renameInfo->FileNameLength > 0) {
                ULONG copyLen = renameInfo->FileNameLength / sizeof(WCHAR);
                if (copyLen >= AKESOEDR_MAX_PATH) {
                    copyLen = AKESOEDR_MAX_PATH - 1;
                }
                RtlStringCchCopyNW(
                    event->Payload.File.NewFilePath,
                    AKESOEDR_MAX_PATH,
                    renameInfo->FileName,
                    copyLen
                );
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "AkesoEDR: Exception 0x%08X in rename handling\n",
                GetExceptionCode()));
        }
    }

    /*
     * Delete: verify the delete flag is actually set.
     * Modern Windows (10 RS5+) may use FILE_DISPOSITION_ON_CLOSE (0x2)
     * instead of FILE_DISPOSITION_DELETE (0x1), so check both.
     */
#ifndef FILE_DISPOSITION_ON_CLOSE
#define FILE_DISPOSITION_ON_CLOSE 0x00000002
#endif
    if (Operation == AkesoEDRFileOpDelete) {
        __try {
            FILE_INFORMATION_CLASS infoClass =
                Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

            if (infoClass == FileDispositionInformation) {
                PFILE_DISPOSITION_INFORMATION dispInfo =
                    (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters
                        .SetFileInformation.InfoBuffer;
                if (dispInfo && !dispInfo->DeleteFile) {
                    goto cleanup;
                }
            } else if (infoClass == FileDispositionInformationEx) {
                PFILE_DISPOSITION_INFORMATION_EX dispInfoEx =
                    (PFILE_DISPOSITION_INFORMATION_EX)Data->Iopb->Parameters
                        .SetFileInformation.InfoBuffer;
                if (dispInfoEx &&
                    !FlagOn(dispInfoEx->Flags,
                            FILE_DISPOSITION_DELETE |
                            FILE_DISPOSITION_ON_CLOSE)) {
                    goto cleanup;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "AkesoEDR: Exception 0x%08X in delete handling\n",
                GetExceptionCode()));
        }
    }

    /* Send event to agent */
    AkesoEDRCommsSend(event);

cleanup:
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }
    ExFreePoolWithTag(event, AKESOEDR_TAG_FILE);
}

/* ── Process context helper ───────────────────────────────────────────── */

/*
 * Fill AKESOEDR_PROCESS_CTX from the I/O callback data.
 * Similar to AkesoEDRFillProcessContext in callbacks_process.c.
 */
void
AkesoEDRMinifilterFillProcessCtx(
    _Out_ AKESOEDR_PROCESS_CTX *Ctx,
    _In_  PFLT_CALLBACK_DATA    Data
)
{
    PEPROCESS       process = NULL;
    PUNICODE_STRING imageName = NULL;

    RtlZeroMemory(Ctx, sizeof(*Ctx));

    Ctx->ProcessId = FltGetRequestorProcessId(Data);
    Ctx->ThreadId  = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

    /*
     * Use the requestor's thread to find the owning process.
     * PsGetCurrentProcess() returns the CURRENT context which in a
     * post-op callback may be a system worker thread, not the
     * original requestor.  Data->Thread is the originating thread.
     */
    if (Data->Thread) {
        process = IoThreadToProcess(Data->Thread);
    }
    if (!process) {
        return;
    }

    Ctx->ParentProcessId =
        (ULONG)(ULONG_PTR)PsGetProcessInheritedFromUniqueProcessId(process);

    {
        ULONG sessionId = 0;
        if (NT_SUCCESS(PsGetProcessSessionId(process, &sessionId))) {
            Ctx->SessionId = sessionId;
        }
    }

    KeQuerySystemTimePrecise(&Ctx->ProcessCreateTime);

    /* Get image file name */
    if (NT_SUCCESS(SeLocateProcessImageName(process, &imageName))) {
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

    /* Token info: user SID, integrity level, elevation */
    AkesoEDRExtractTokenInfoMf(
        process,
        Ctx->UserSid,
        AKESOEDR_MAX_SID_STRING,
        &Ctx->IntegrityLevel,
        &Ctx->IsElevated
    );
}

/* ── Token info extraction ────────────────────────────────────────────── */

/*
 * Extract user SID, integrity level, and elevation status from
 * the process token.  Duplicated from callbacks_process.c to avoid
 * cross-file static linkage issues (kernel C has no LTO by default).
 */
static void
AkesoEDRExtractTokenInfoMf(
    _In_  PEPROCESS Process,
    _Out_ WCHAR    *SidBuffer,
    _In_  ULONG     SidBufferLen,
    _Out_ ULONG    *IntegrityLevel,
    _Out_ BOOLEAN  *IsElevated
)
{
    NTSTATUS        status;
    PACCESS_TOKEN   token = NULL;
    PTOKEN_USER     tokenUser = NULL;

    SidBuffer[0] = L'\0';
    *IntegrityLevel = 0;
    *IsElevated = FALSE;

    token = PsReferencePrimaryToken(Process);
    if (!token) {
        return;
    }

    /* User SID */
    status = SeQueryInformationToken(token, TokenUser, (PVOID *)&tokenUser);
    if (NT_SUCCESS(status) && tokenUser) {
        AkesoEDRSidToStringMf(tokenUser->User.Sid, SidBuffer, SidBufferLen);
        ExFreePool(tokenUser);
    }

    /* Integrity level */
    {
        PTOKEN_MANDATORY_LABEL label = NULL;
        status = SeQueryInformationToken(
            token, TokenIntegrityLevel, (PVOID *)&label);
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

    /* Elevation */
    {
        PTOKEN_ELEVATION pElevation = NULL;
        status = SeQueryInformationToken(
            token, TokenElevation, (PVOID *)&pElevation);
        if (NT_SUCCESS(status) && pElevation) {
            *IsElevated = (pElevation->TokenIsElevated != 0);
            ExFreePool(pElevation);
        }
    }

    PsDereferencePrimaryToken(token);
}

/* ── SID to string ────────────────────────────────────────────────────── */

static void
AkesoEDRSidToStringMf(
    _In_  PSID    Sid,
    _Out_ WCHAR  *Buffer,
    _In_  ULONG   BufferLen
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
