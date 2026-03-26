/*
 * akesoedr-drv/callbacks_imageload.c
 * Image-load callback implementation (Ch. 5 — PsSetLoadImageNotifyRoutineEx).
 *
 * On every image (EXE, DLL, driver) load on the system, this callback:
 *   1. Populates a AKESOEDR_EVENT with image metadata
 *   2. Determines signing status via IMAGE_INFO signature fields
 *   3. Sends the event to the agent over the filter communication port
 *
 * Noise reduction: kernel-mode image loads (drivers) are skipped by default
 * since we primarily care about user-mode DLL/EXE loads for detection.
 *
 * IRQL: The callback runs at PASSIVE_LEVEL (guaranteed by the OS).
 *
 * Book reference: Chapter 5 — Image-Load and Registry Notifications.
 */

#include <fltKernel.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#include "callbacks_imageload.h"
#include "kapc_inject.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "self_protect.h"

/* ── Undocumented but stable kernel APIs ────────────────────────────────── */

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

/* ── Signature level constants (ntddk.h may not define all of these) ───── */

#ifndef SE_SIGNING_LEVEL_UNSIGNED
#define SE_SIGNING_LEVEL_UNSIGNED       0x00
#endif

#ifndef SE_SIGNING_LEVEL_AUTHENTICODE
#define SE_SIGNING_LEVEL_AUTHENTICODE   0x04
#endif

/* ── PE certificate check helper declaration ────────────────────────────── */

static BOOLEAN
AkesoEDRCheckImageSigned(
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PBOOLEAN   IsValid
);

/* ── Forward declarations ───────────────────────────────────────────────── */

static VOID
AkesoEDRImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
);

static VOID
AkesoEDRFillProcessCtxForImageLoad(
    _Out_ AKESOEDR_PROCESS_CTX* Ctx,
    _In_  HANDLE                ProcessId
);

/* ── Section placement ──────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AkesoEDRImageLoadCallbackInit)
#pragma alloc_text(PAGE, AkesoEDRImageLoadCallbackStop)
#endif

/* ── State ──────────────────────────────────────────────────────────────── */

static BOOLEAN g_ImageLoadCallbackRegistered = FALSE;

/* ── Public API ─────────────────────────────────────────────────────────── */

NTSTATUS
AkesoEDRImageLoadCallbackInit(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    if (g_ImageLoadCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    /*
     * PsSetLoadImageNotifyRoutineEx accepts a Flags parameter.
     * Flag 0 = standard behavior (notify for all image loads).
     * If the Ex variant is unavailable (pre-Win10 1709), fall back
     * to PsSetLoadImageNotifyRoutine.
     */
    status = PsSetLoadImageNotifyRoutineEx(
        AkesoEDRImageLoadCallback,
        0       /* Flags — standard behavior */
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "AkesoEDR: PsSetLoadImageNotifyRoutineEx failed 0x%08X, "
            "falling back to legacy API\n", status));

        status = PsSetLoadImageNotifyRoutine(AkesoEDRImageLoadCallback);

        if (!NT_SUCCESS(status)) {
            KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "AkesoEDR: PsSetLoadImageNotifyRoutine failed 0x%08X\n",
                status));
            return status;
        }
    }

    g_ImageLoadCallbackRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Image-load callback registered\n"));

    return STATUS_SUCCESS;
}

VOID
AkesoEDRImageLoadCallbackStop(VOID)
{
    PAGED_CODE();

    if (!g_ImageLoadCallbackRegistered) {
        return;
    }

    PsRemoveLoadImageNotifyRoutine(AkesoEDRImageLoadCallback);

    g_ImageLoadCallbackRegistered = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Image-load callback unregistered\n"));
}

/* ── Callback implementation ────────────────────────────────────────────── */

/*
 * PsSetLoadImageNotifyRoutine(Ex) callback.
 *
 * Called for every image load (EXE, DLL, driver) system-wide.
 *
 * ProcessId == 0 means a kernel-mode driver is being loaded.
 * ImageInfo->SystemModeImage indicates the image is mapped into
 * kernel address space.
 *
 * Signing status: On Win10+, IMAGE_INFO contains ImageSignatureLevel
 * and ImageSignatureType as bit fields. We use these to determine
 * whether the image is signed and whether the signature is valid.
 */
static VOID
AkesoEDRImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
)
{
    AKESOEDR_EVENT *event;

    AkesoEDRCanaryImageLoadCallback();

    if (!ImageInfo) {
        return;
    }

    /*
     * Skip kernel-mode image loads (drivers) to reduce noise.
     * We primarily care about user-mode DLL/EXE loads for
     * detection purposes (credential dumping DLLs, injection, etc.).
     */
    if (ImageInfo->SystemModeImage) {
        return;
    }

    /* Skip PID 0 (system/idle) loads */
    if ((ULONG_PTR)ProcessId == 0) {
        return;
    }

    /*
     * KAPC injection — two-phase approach:
     *
     * Phase 1 (ntdll.dll): Save the ntdll base address for this PID.
     *   ntdll loads on the parent's thread (during NtCreateUserProcess),
     *   so we can't queue APCs yet — KeGetCurrentThread() is wrong.
     *
     * Phase 2 (kernel32.dll): Resolve LdrLoadDll from saved ntdll base,
     *   allocate shellcode, queue KAPC. By kernel32 load time, the initial
     *   thread is executing and KeGetCurrentThread() is correct.
     */
    if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
        USHORT  nameLen = FullImageName->Length / sizeof(WCHAR);
        PCWCH   nameBuf = FullImageName->Buffer;

        /* Phase 1: "\ntdll.dll" (10 chars) — save ntdll base */
        if (nameLen >= 10) {
            PCWCH tail = nameBuf + nameLen - 10;

            if ((tail[0] == L'\\' || tail[0] == L'/') &&
                (tail[1] == L'n' || tail[1] == L'N') &&
                (tail[2] == L't' || tail[2] == L'T') &&
                (tail[3] == L'd' || tail[3] == L'D') &&
                (tail[4] == L'l' || tail[4] == L'L') &&
                (tail[5] == L'l' || tail[5] == L'L') &&
                (tail[6] == L'.') &&
                (tail[7] == L'd' || tail[7] == L'D') &&
                (tail[8] == L'l' || tail[8] == L'L') &&
                (tail[9] == L'l' || tail[9] == L'L'))
            {
                AkesoEDRKapcSaveNtdllBase(ProcessId, ImageInfo->ImageBase);
            }
        }

        /* Phase 2: "\kernel32.dll" (13 chars) — inject */
        if (nameLen >= 13) {
            PCWCH tail = nameBuf + nameLen - 13;

            if ((tail[0]  == L'\\' || tail[0]  == L'/') &&
                (tail[1]  == L'k'  || tail[1]  == L'K') &&
                (tail[2]  == L'e'  || tail[2]  == L'E') &&
                (tail[3]  == L'r'  || tail[3]  == L'R') &&
                (tail[4]  == L'n'  || tail[4]  == L'N') &&
                (tail[5]  == L'e'  || tail[5]  == L'E') &&
                (tail[6]  == L'l'  || tail[6]  == L'L') &&
                (tail[7]  == L'3'                      ) &&
                (tail[8]  == L'2'                      ) &&
                (tail[9]  == L'.'                      ) &&
                (tail[10] == L'd'  || tail[10] == L'D') &&
                (tail[11] == L'l'  || tail[11] == L'L') &&
                (tail[12] == L'l'  || tail[12] == L'L'))
            {
                AkesoEDRKapcTryInject(ProcessId);
            }
        }
    }

    /* ── Allocate and fill event ────────────────────────────────────────── */

    event = (AKESOEDR_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AKESOEDR_EVENT), AKESOEDR_TAG_EVENT);
    if (!event) {
        return;
    }

    __try {
        RtlZeroMemory(event, sizeof(AKESOEDR_EVENT));
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
        event->Source   = AkesoEDRSourceDriverImageLoad;
        event->Severity = AkesoEDRSeverityInformational;

        /* Fill process context for the loading process */
        AkesoEDRFillProcessCtxForImageLoad(&event->ProcessCtx, ProcessId);

        /* Fill image-load payload */
        event->Payload.ImageLoad.ProcessId = (ULONG)(ULONG_PTR)ProcessId;

        /* Image path */
        if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
            RtlStringCchCopyNW(
                event->Payload.ImageLoad.ImagePath,
                AKESOEDR_MAX_PATH,
                FullImageName->Buffer,
                FullImageName->Length / sizeof(WCHAR));
        }

        /* Image base and size */
        event->Payload.ImageLoad.ImageBase = (ULONG_PTR)ImageInfo->ImageBase;
        event->Payload.ImageLoad.ImageSize = ImageInfo->ImageSize;

        /* Kernel vs user mode */
        event->Payload.ImageLoad.IsKernelImage = ImageInfo->SystemModeImage;

        /*
         * Signing status: try IMAGE_INFO bit fields first (Win10+),
         * fall back to PE certificate directory check via IMAGE_INFO_EX.
         */
        {
            BOOLEAN isSigned = FALSE;
            BOOLEAN isValid  = FALSE;
            ULONG sigLevel = ImageInfo->ImageSignatureLevel;

            if (sigLevel > SE_SIGNING_LEVEL_UNSIGNED) {
                /* Kernel populated the signature level — use it */
                isSigned = TRUE;
                isValid  = (sigLevel >= SE_SIGNING_LEVEL_AUTHENTICODE);
            } else {
                /*
                 * Signature level is 0 — common on test-signing-enabled
                 * VMs or older Win10 builds. Fall back to checking the PE
                 * IMAGE_DIRECTORY_ENTRY_SECURITY via the file object.
                 */
                isSigned = AkesoEDRCheckImageSigned(ImageInfo, &isValid);
            }

            event->Payload.ImageLoad.IsSigned = isSigned;
            event->Payload.ImageLoad.IsSignatureValid = isValid;
        }

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "AkesoEDR: ImageLoad PID=%lu Base=0x%p Size=0x%IX Signed=%d %wZ\n",
            (ULONG)(ULONG_PTR)ProcessId,
            ImageInfo->ImageBase,
            ImageInfo->ImageSize,
            event->Payload.ImageLoad.IsSigned,
            FullImageName));

        AkesoEDRCommsSend(event);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: Exception 0x%08X in image-load callback PID=%lu\n",
            GetExceptionCode(),
            (ULONG)(ULONG_PTR)ProcessId));
    }

    ExFreePoolWithTag(event, AKESOEDR_TAG_EVENT);
}

/* ── Helper: check PE Authenticode signature via file object ────────────── */

/*
 * AkesoEDRCheckImageSigned
 *
 * When IMAGE_INFO.ImageSignatureLevel is not populated (common on
 * test-signing-enabled VMs), we fall back to reading the PE header's
 * IMAGE_DIRECTORY_ENTRY_SECURITY to check if an Authenticode
 * certificate table is present.
 *
 * This requires IMAGE_INFO_EX (ExtendedInfoPresent == TRUE) to get
 * the FileObject, then reads the PE header from the mapped image.
 *
 * Returns TRUE if signed (has certificate table), FALSE otherwise.
 * Sets *IsValid to TRUE if certificate table size > 0 (basic check).
 */
static BOOLEAN
AkesoEDRCheckImageSigned(
    _In_ PIMAGE_INFO ImageInfo,
    _Out_ PBOOLEAN   IsValid
)
{
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_NT_HEADERS       ntHeaders;
    IMAGE_DATA_DIRECTORY    securityDir;

    *IsValid = FALSE;

    if (!ImageInfo->ImageBase) {
        return FALSE;
    }

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)(
            (PUCHAR)ImageInfo->ImageBase + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }

        /*
         * IMAGE_DIRECTORY_ENTRY_SECURITY = 4
         * Check if the certificate table data directory is populated.
         */
        if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;

            if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                return FALSE;
            }

            securityDir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHeaders;

            if (nt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                return FALSE;
            }

            securityDir = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else {
            return FALSE;
        }

        /*
         * If VirtualAddress and Size are nonzero, the PE has an
         * embedded Authenticode certificate table. This is a basic
         * presence check — not a full signature verification.
         */
        if (securityDir.VirtualAddress != 0 && securityDir.Size > 0) {
            *IsValid = TRUE;  /* Has certificate — assume valid for POC */
            return TRUE;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "AkesoEDR: Exception checking PE signature: 0x%08X\n",
            GetExceptionCode()));
    }

    return FALSE;
}

/* ── Helper: fill process context for the loading process ──────────────── */

static VOID
AkesoEDRFillProcessCtxForImageLoad(
    _Out_ AKESOEDR_PROCESS_CTX* Ctx,
    _In_  HANDLE                ProcessId
)
{
    PEPROCESS       process = NULL;
    NTSTATUS        status;
    PUNICODE_STRING imageName = NULL;

    RtlZeroMemory(Ctx, sizeof(AKESOEDR_PROCESS_CTX));

    Ctx->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    Ctx->ThreadId  = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();

    /* Look up the process */
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status) || !process) {
        return;
    }

    /* Parent PID */
    Ctx->ParentProcessId = (ULONG)(ULONG_PTR)
        PsGetProcessInheritedFromUniqueProcessId(process);

    /* Session ID */
    {
        ULONG sessionId = 0;
        NTSTATUS sessionStatus = PsGetProcessSessionId(process, &sessionId);
        Ctx->SessionId = NT_SUCCESS(sessionStatus) ? sessionId : 0;
    }

    KeQuerySystemTimePrecise(&Ctx->ProcessCreateTime);

    /* Image path */
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

    ObDereferenceObject(process);
}
