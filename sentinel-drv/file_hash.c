/*
 * sentinel-drv/file_hash.c
 * Asynchronous SHA-256 file hashing for minifilter post-create events.
 *
 * When a file is created or overwritten (FILE_CREATED, FILE_OVERWRITTEN,
 * FILE_SUPERSEDED), the post-create callback queues a work item that:
 *   1. Re-opens the file below our minifilter altitude
 *   2. Reads it in 64 KB chunks
 *   3. Computes SHA-256 via the kernel BCrypt API
 *   4. Emits a SENTINEL_EVENT with the hash and file metadata
 *
 * This keeps the I/O path non-blocking — the work item runs at
 * PASSIVE_LEVEL on a system worker thread.
 *
 * Files larger than SENTINEL_SCAN_MAX_FILE_SIZE (50 MB) are skipped
 * with HashSkipped = TRUE.
 *
 * IRQL:
 *   - SentinelFileHashQueueWorkItem: <= APC_LEVEL (post-op callback)
 *   - Work item callback: PASSIVE_LEVEL
 *   - BCrypt*, FltCreateFileEx2, FltReadFile: PASSIVE_LEVEL
 *
 * P5-T2: File Hashing.
 */

#include <fltKernel.h>
#include <bcrypt.h>
#include <ntstrsafe.h>

#include "file_hash.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "minifilter.h"

/* ── Extern globals from main.c ─────────────────────────────────────────── */

extern PDEVICE_OBJECT  g_DeviceObject;
extern PFLT_FILTER     g_FilterHandle;

/* ── Constants ──────────────────────────────────────────────────────────── */

#define FILE_HASH_READ_CHUNK    (64 * 1024)     /* 64 KB read buffer */
#define SHA256_HASH_SIZE        32              /* SHA-256 = 32 bytes raw */

/* ── File-scoped globals ────────────────────────────────────────────────── */

static BCRYPT_ALG_HANDLE g_Sha256AlgHandle = NULL;
static volatile LONG     g_HashWorkItemsActive = 0;

/* ── Work item context ──────────────────────────────────────────────────── */

typedef struct _SENTINEL_HASH_WORK_CTX {
    PIO_WORKITEM         WorkItem;
    PFLT_FILTER          Filter;
    PFLT_INSTANCE        Instance;          /* FltObjectReference'd */
    SENTINEL_FILE_OP     Operation;
    ULONG                RequestingProcessId;
    WCHAR                FilePath[SENTINEL_MAX_PATH];
    LARGE_INTEGER        FileSize;
    SENTINEL_PROCESS_CTX ProcessCtx;
    LARGE_INTEGER        Timestamp;
    GUID                 EventId;
} SENTINEL_HASH_WORK_CTX;

/* ── Forward declarations ───────────────────────────────────────────────── */

static VOID
SentinelFileHashWorkItemCb(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID          Context
);

static NTSTATUS
SentinelFileHashComputeSha256(
    _In_    PFLT_FILTER     Filter,
    _In_    PFLT_INSTANCE   Instance,
    _In_    const WCHAR    *FilePath,
    _Inout_ LARGE_INTEGER  *FileSize,
    _Out_   CHAR           *Sha256Hex,
    _Out_   BOOLEAN        *HashSkipped
);

static void
SentinelHashBytesToHex(
    _In_  const UCHAR *Bytes,
    _In_  ULONG        ByteCount,
    _Out_ CHAR        *HexBuffer
);

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

NTSTATUS
SentinelFileHashInit(VOID)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(
        &g_Sha256AlgHandle,
        BCRYPT_SHA256_ALGORITHM,
        NULL,       /* MS_PRIMITIVE_PROVIDER (default) */
        0           /* Flags */
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: BCryptOpenAlgorithmProvider failed 0x%08X\n",
            status));
        g_Sha256AlgHandle = NULL;
        return status;
    }

    g_HashWorkItemsActive = 0;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: File hash subsystem initialized (SHA-256)\n"));

    return STATUS_SUCCESS;
}

VOID
SentinelFileHashStop(VOID)
{
    LARGE_INTEGER waitInterval;
    LONG          spins = 0;

    /*
     * Wait for in-flight work items to complete.
     * Each work item increments g_HashWorkItemsActive on queue
     * and decrements on completion.
     */
    waitInterval.QuadPart = -10 * 1000 * 100;  /* 100 ms in 100-ns units */

    while (InterlockedCompareExchange(&g_HashWorkItemsActive, 0, 0) > 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &waitInterval);
        if (++spins > 50) {     /* 5 seconds max */
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "SentinelPOC: Timed out waiting for %ld hash work items\n",
                g_HashWorkItemsActive));
            break;
        }
    }

    if (g_Sha256AlgHandle) {
        BCryptCloseAlgorithmProvider(g_Sha256AlgHandle, 0);
        g_Sha256AlgHandle = NULL;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "SentinelPOC: File hash subsystem stopped\n"));
}

/* ── Queue work item ────────────────────────────────────────────────────── */

VOID
SentinelFileHashQueueWorkItem(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SENTINEL_FILE_OP      Operation
)
{
    SENTINEL_HASH_WORK_CTX *ctx = NULL;
    NTSTATUS                status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    /* Don't queue if hash subsystem isn't ready */
    if (!g_Sha256AlgHandle || !g_DeviceObject) {
        goto fallback;
    }

    /* Don't queue if agent isn't connected */
    if (!SentinelCommsIsConnected()) {
        return;
    }

    /* Allocate work item context */
    ctx = (SENTINEL_HASH_WORK_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SENTINEL_HASH_WORK_CTX),
        SENTINEL_TAG_HASH
    );
    if (!ctx) {
        goto fallback;
    }

    RtlZeroMemory(ctx, sizeof(*ctx));

    /* Fill context fields */
    ctx->Filter = g_FilterHandle;
    ctx->Operation = Operation;
    ctx->RequestingProcessId = FltGetRequestorProcessId(Data);

    /* UUID + timestamp */
    __try {
        ExUuidCreate(&ctx->EventId);
        KeQuerySystemTimePrecise(&ctx->Timestamp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal — fields stay zeroed */
    }

    /* Process context */
    __try {
        SentinelMinifilterFillProcessCtx(&ctx->ProcessCtx, Data);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal */
    }

    /* File path */
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
                ctx->FilePath,
                SENTINEL_MAX_PATH,
                nameInfo->Name.Buffer,
                nameInfo->Name.Length / sizeof(WCHAR)
            );
            FltReleaseFileNameInformation(nameInfo);
            nameInfo = NULL;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal — path stays empty */
    }

    /* File size query */
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
            ctx->FileSize = stdInfo.EndOfFile;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Non-fatal — size stays 0 */
    }

    /* Reference the filter instance to keep it alive until work item runs */
    status = FltObjectReference(FltObjects->Instance);
    if (!NT_SUCCESS(status)) {
        goto fallback_free;
    }
    ctx->Instance = FltObjects->Instance;

    /* Allocate and queue the work item */
    ctx->WorkItem = IoAllocateWorkItem(g_DeviceObject);
    if (!ctx->WorkItem) {
        FltObjectDereference(ctx->Instance);
        goto fallback_free;
    }

    InterlockedIncrement(&g_HashWorkItemsActive);

    IoQueueWorkItem(
        ctx->WorkItem,
        SentinelFileHashWorkItemCb,
        DelayedWorkQueue,
        ctx
    );

    return;

fallback_free:
    if (nameInfo) {
        FltReleaseFileNameInformation(nameInfo);
    }
    if (ctx) {
        ExFreePoolWithTag(ctx, SENTINEL_TAG_HASH);
    }

fallback:
    /* Fall back to synchronous event emission without hash */
    SentinelMinifilterEmitFileEvent(Data, FltObjects, Operation);
}

/* ── Work item callback ─────────────────────────────────────────────────── */

static VOID
SentinelFileHashWorkItemCb(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID          Context
)
{
    SENTINEL_HASH_WORK_CTX *ctx = (SENTINEL_HASH_WORK_CTX *)Context;
    SENTINEL_EVENT         *event = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!ctx) {
        goto done;
    }

    /*
     * Brief delay to let pending writes flush.
     * PostCreate fires before the first WRITE IRP, so hashing immediately
     * would see a zero-length file.  500 ms is enough for typical creates
     * (echo, copy, Set-Content) without materially delaying telemetry.
     * Production EDRs solve this by hashing on IRP_MJ_CLEANUP instead.
     */
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -500 * 10000LL;   /* 500 ms in 100-ns units */
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    /* Allocate event */
    event = (SENTINEL_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SENTINEL_EVENT),
        SENTINEL_TAG_FILE
    );
    if (!event) {
        goto done;
    }

    RtlZeroMemory(event, sizeof(SENTINEL_EVENT));

    /* Fill event envelope from captured context */
    event->EventId   = ctx->EventId;
    event->Timestamp = ctx->Timestamp;
    event->Source     = SentinelSourceDriverMinifilter;
    event->Severity  = SentinelSeverityInformational;
    event->ProcessCtx = ctx->ProcessCtx;

    /* Fill file payload */
    event->Payload.File.Operation = ctx->Operation;
    event->Payload.File.RequestingProcessId = ctx->RequestingProcessId;
    event->Payload.File.FileSize = ctx->FileSize;

    RtlStringCchCopyW(
        event->Payload.File.FilePath,
        SENTINEL_MAX_PATH,
        ctx->FilePath
    );

    /* Compute SHA-256 hash */
    if (ctx->FilePath[0] != L'\0' && ctx->Instance) {
        __try {
            SentinelFileHashComputeSha256(
                ctx->Filter,
                ctx->Instance,
                ctx->FilePath,
                &ctx->FileSize,
                event->Payload.File.Sha256Hex,
                &event->Payload.File.HashSkipped
            );
            /* Update event with actual file size from re-query */
            event->Payload.File.FileSize = ctx->FileSize;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SentinelPOC: Exception 0x%08X in hash computation\n",
                GetExceptionCode()));
        }
    }

    /* Send event to agent */
    SentinelCommsSend(event);

    ExFreePoolWithTag(event, SENTINEL_TAG_FILE);

done:
    if (ctx) {
        if (ctx->Instance) {
            FltObjectDereference(ctx->Instance);
        }
        if (ctx->WorkItem) {
            IoFreeWorkItem(ctx->WorkItem);
        }
        ExFreePoolWithTag(ctx, SENTINEL_TAG_HASH);
    }

    InterlockedDecrement(&g_HashWorkItemsActive);
}

/* ── SHA-256 computation ────────────────────────────────────────────────── */

static NTSTATUS
SentinelFileHashComputeSha256(
    _In_    PFLT_FILTER     Filter,
    _In_    PFLT_INSTANCE   Instance,
    _In_    const WCHAR    *FilePath,
    _Inout_ LARGE_INTEGER  *FileSize,
    _Out_   CHAR           *Sha256Hex,
    _Out_   BOOLEAN        *HashSkipped
)
{
    NTSTATUS            status;
    HANDLE              fileHandle = NULL;
    PFILE_OBJECT        fileObject = NULL;
    BCRYPT_HASH_HANDLE  hHash = NULL;
    PUCHAR              readBuffer = NULL;
    UCHAR               rawHash[SHA256_HASH_SIZE];
    UNICODE_STRING      filePath;
    OBJECT_ATTRIBUTES   objAttr;
    IO_STATUS_BLOCK     ioStatus;
    LARGE_INTEGER       offset;
    LONGLONG            bytesRemaining;

    Sha256Hex[0] = '\0';
    *HashSkipped = FALSE;

    /*
     * Don't early-return based on the initial FileSize — it may be stale
     * (e.g., 0 at PostCreate time before writes land).  We always re-open
     * and re-query the actual size below.  Only skip if we already know
     * the file is definitely too large.
     */
    if (FileSize->QuadPart > SENTINEL_SCAN_MAX_FILE_SIZE) {
        *HashSkipped = TRUE;
        return STATUS_SUCCESS;
    }

    /* Open file below our minifilter for reading */
    RtlInitUnicodeString(&filePath, FilePath);
    InitializeObjectAttributes(
        &objAttr,
        &filePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = FltCreateFileEx(
        Filter,
        Instance,
        &fileHandle,
        &fileObject,
        GENERIC_READ,
        &objAttr,
        &ioStatus,
        NULL,                               /* AllocationSize */
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,                          /* Must exist */
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,                               /* EaBuffer */
        0,                                  /* EaLength */
        0                                   /* Flags */
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "SentinelPOC: FltCreateFileEx failed 0x%08X for hash\n", status));
        return status;
    }

    /*
     * Re-query the actual file size now that the file is fully written.
     * The size captured in PostCreate may be 0 (e.g. fsutil createNew
     * creates the file first, then extends it).
     */
    {
        FILE_STANDARD_INFORMATION stdInfo = { 0 };
        status = FltQueryInformationFile(
            Instance,
            fileObject,
            &stdInfo,
            sizeof(stdInfo),
            FileStandardInformation,
            NULL
        );
        if (NT_SUCCESS(status)) {
            *FileSize = stdInfo.EndOfFile;

            /* Re-check size cap with actual size */
            if (FileSize->QuadPart > SENTINEL_SCAN_MAX_FILE_SIZE) {
                *HashSkipped = TRUE;
                goto cleanup;
            }

            /* Re-check for zero-length */
            if (FileSize->QuadPart == 0) {
                RtlStringCchCopyA(Sha256Hex, SENTINEL_MAX_HASH_HEX,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                goto cleanup;
            }
        }
        /* If query fails, proceed with original FileSize */
    }

    /* Allocate read buffer */
    readBuffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        FILE_HASH_READ_CHUNK,
        SENTINEL_TAG_HASH
    );
    if (!readBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    /* Create hash object */
    status = BCryptCreateHash(
        g_Sha256AlgHandle,
        &hHash,
        NULL, 0,        /* Let BCrypt allocate hash object internally */
        NULL, 0,        /* No secret (not HMAC) */
        0               /* Flags */
    );
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: BCryptCreateHash failed 0x%08X\n", status));
        goto cleanup;
    }

    /* Read file in chunks and feed to hash */
    offset.QuadPart = 0;
    bytesRemaining = FileSize->QuadPart;

    while (bytesRemaining > 0) {
        ULONG chunkSize = (ULONG)min(bytesRemaining, FILE_HASH_READ_CHUNK);
        ULONG bytesRead = 0;

        status = FltReadFile(
            Instance,
            fileObject,
            &offset,
            chunkSize,
            readBuffer,
            FLTFL_IO_OPERATION_NON_CACHED,
            &bytesRead,
            NULL,       /* CallbackRoutine */
            NULL        /* CallbackContext */
        );

        if (!NT_SUCCESS(status) || bytesRead == 0) {
            /* File may have been truncated or deleted — hash what we have */
            break;
        }

        status = BCryptHashData(hHash, readBuffer, bytesRead, 0);
        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SentinelPOC: BCryptHashData failed 0x%08X\n", status));
            goto cleanup;
        }

        offset.QuadPart += bytesRead;
        bytesRemaining -= bytesRead;
    }

    /* Finalize hash */
    status = BCryptFinishHash(hHash, rawHash, SHA256_HASH_SIZE, 0);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "SentinelPOC: BCryptFinishHash failed 0x%08X\n", status));
        goto cleanup;
    }

    /* Convert to hex string */
    SentinelHashBytesToHex(rawHash, SHA256_HASH_SIZE, Sha256Hex);

    status = STATUS_SUCCESS;

cleanup:
    if (hHash) {
        BCryptDestroyHash(hHash);
    }
    if (readBuffer) {
        ExFreePoolWithTag(readBuffer, SENTINEL_TAG_HASH);
    }
    if (fileObject) {
        ObDereferenceObject(fileObject);
    }
    if (fileHandle) {
        FltClose(fileHandle);
    }

    return status;
}

/* ── Hex encoding ───────────────────────────────────────────────────────── */

static void
SentinelHashBytesToHex(
    _In_  const UCHAR *Bytes,
    _In_  ULONG        ByteCount,
    _Out_ CHAR        *HexBuffer
)
{
    static const CHAR hexChars[] = "0123456789abcdef";
    ULONG i;

    for (i = 0; i < ByteCount; i++) {
        HexBuffer[i * 2]     = hexChars[Bytes[i] >> 4];
        HexBuffer[i * 2 + 1] = hexChars[Bytes[i] & 0x0F];
    }
    HexBuffer[ByteCount * 2] = '\0';
}
