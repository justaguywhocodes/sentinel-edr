/*
 * akesoedr-drv/callbacks_registry.c
 * Registry callback implementation (Ch. 5 — CmRegisterCallbackEx).
 *
 * Monitors registry operations: key create, value set/delete,
 * key delete, key rename. Emits telemetry events with full key path,
 * value name, data type, and data content (truncated at 4KB).
 *
 * Noise filtering excludes high-frequency Explorer and BAM writes.
 *
 * IRQL: Registry callbacks run at PASSIVE_LEVEL.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "callbacks_registry.h"
#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "self_protect.h"

/* ── Undocumented but stable kernel APIs ────────────────────────────────── */

NTKERNELAPI
PCHAR
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

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

/* ── Section placement ─────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, AkesoEDRRegistryCallbackInit)
#pragma alloc_text(PAGE, AkesoEDRRegistryCallbackStop)
#endif

/* ── State ─────────────────────────────────────────────────────────────── */

static BOOLEAN          g_RegistryCallbackRegistered = FALSE;
static LARGE_INTEGER    g_RegCookie = { 0 };

/* ── Noise filter patterns (case-insensitive substring match) ──────────── */

static const WCHAR* g_RegistryNoisePatterns[] = {
    L"\\CurrentVersion\\Explorer",
    L"\\Services\\bam\\State",
    L"\\Notifications\\",
    L"\\Explorer\\SessionInfo",
    L"\\Explorer\\User Shell Folders",
};

#define NOISE_PATTERN_COUNT (sizeof(g_RegistryNoisePatterns) / sizeof(g_RegistryNoisePatterns[0]))

/* ── Forward declarations ──────────────────────────────────────────────── */

static NTSTATUS
AkesoEDRRegistryCallback(
    _In_     PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
);

static BOOLEAN
AkesoEDRRegistryIsNoisy(
    _In_ PCUNICODE_STRING KeyPath
);

static VOID
AkesoEDRFillProcessCtxForRegistry(
    _Out_ AKESOEDR_PROCESS_CTX* Ctx,
    _In_  HANDLE                ProcessId
);

static VOID
AkesoEDREmitRegistryEvent(
    _In_     AKESOEDR_REG_OP    Operation,
    _In_     PCUNICODE_STRING   KeyPath,
    _In_opt_ PCUNICODE_STRING   ValueName,
    _In_     ULONG              DataType,
    _In_opt_ PVOID              Data,
    _In_     ULONG              DataSize
);

/* ── AkesoEDRRegistryCallbackInit ──────────────────────────────────────── */

NTSTATUS
AkesoEDRRegistryCallbackInit(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    NTSTATUS        status;
    UNICODE_STRING  altitude;

    PAGED_CODE();

    if (g_RegistryCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&altitude, L"385200");

    status = CmRegisterCallbackEx(
        AkesoEDRRegistryCallback,
        &altitude,
        DriverObject,
        NULL,       /* Context */
        &g_RegCookie,
        NULL        /* Reserved */
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: CmRegisterCallbackEx failed 0x%08X\n", status));
        return status;
    }

    g_RegistryCallbackRegistered = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Registry callback registered (altitude %wZ)\n",
        &altitude));

    return STATUS_SUCCESS;
}

/* ── AkesoEDRRegistryCallbackStop ──────────────────────────────────────── */

VOID
AkesoEDRRegistryCallbackStop(VOID)
{
    PAGED_CODE();

    if (!g_RegistryCallbackRegistered) {
        return;
    }

    CmUnRegisterCallback(g_RegCookie);
    g_RegCookie.QuadPart       = 0;
    g_RegistryCallbackRegistered = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Registry callback unregistered\n"));
}

/* ── Noise filter ──────────────────────────────────────────────────────── */

static BOOLEAN
AkesoEDRRegistryIsNoisy(
    _In_ PCUNICODE_STRING KeyPath
)
{
    UNICODE_STRING  pattern;
    ULONG           i;

    if (!KeyPath || !KeyPath->Buffer || KeyPath->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < NOISE_PATTERN_COUNT; i++) {
        RtlInitUnicodeString(&pattern, g_RegistryNoisePatterns[i]);

        /*
         * Simple case-insensitive substring search:
         * Walk the key path looking for the pattern.
         */
        if (KeyPath->Length >= pattern.Length) {
            USHORT maxOffset = (KeyPath->Length - pattern.Length) / sizeof(WCHAR);
            USHORT j;

            for (j = 0; j <= maxOffset; j++) {
                UNICODE_STRING slice;
                slice.Buffer        = KeyPath->Buffer + j;
                slice.Length         = pattern.Length;
                slice.MaximumLength = pattern.Length;

                if (RtlEqualUnicodeString(&slice, &pattern, TRUE)) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/* ── Registry callback ─────────────────────────────────────────────────── */

static NTSTATUS
AkesoEDRRegistryCallback(
    _In_     PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    REG_NOTIFY_CLASS    notifyClass;
    PCUNICODE_STRING    objectName = NULL;
    PVOID               keyObject  = NULL;
    NTSTATUS            status;

    UNREFERENCED_PARAMETER(CallbackContext);

    AkesoEDRCanaryRegistryCallback();

    if (!Argument1 || !Argument2) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (notifyClass) {

    /* ── Post-create key ──────────────────────────────────────────────── */
    case RegNtPostCreateKeyEx: {
        PREG_POST_OPERATION_INFORMATION postInfo =
            (PREG_POST_OPERATION_INFORMATION)Argument2;

        if (!NT_SUCCESS(postInfo->Status) || !postInfo->Object) {
            break;
        }

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegCookie, postInfo->Object, NULL, &objectName, 0);
        if (!NT_SUCCESS(status) || !objectName) {
            break;
        }

        if (!AkesoEDRRegistryIsNoisy(objectName)) {
            /* Only emit if a new key was actually created */
            PREG_CREATE_KEY_INFORMATION_V1 preInfo =
                (PREG_CREATE_KEY_INFORMATION_V1)postInfo->PreInformation;
            if (preInfo && preInfo->CompleteName) {
                AkesoEDREmitRegistryEvent(
                    AkesoEDRRegOpCreateKey, objectName,
                    NULL, 0, NULL, 0);
            }
        }

        CmCallbackReleaseKeyObjectIDEx(objectName);
        break;
    }

    /* ── Post-set value ───────────────────────────────────────────────── */
    case RegNtPostSetValueKey: {
        PREG_POST_OPERATION_INFORMATION postInfo =
            (PREG_POST_OPERATION_INFORMATION)Argument2;
        PREG_SET_VALUE_KEY_INFORMATION setInfo;

        if (!NT_SUCCESS(postInfo->Status) || !postInfo->Object) {
            break;
        }

        setInfo = (PREG_SET_VALUE_KEY_INFORMATION)postInfo->PreInformation;
        if (!setInfo) {
            break;
        }

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegCookie, postInfo->Object, NULL, &objectName, 0);
        if (!NT_SUCCESS(status) || !objectName) {
            break;
        }

        if (!AkesoEDRRegistryIsNoisy(objectName)) {
            ULONG dataSize = setInfo->DataSize;
            if (dataSize > AKESOEDR_MAX_REG_DATA) {
                dataSize = AKESOEDR_MAX_REG_DATA;
            }

            AkesoEDREmitRegistryEvent(
                AkesoEDRRegOpSetValue, objectName,
                setInfo->ValueName,
                setInfo->Type,
                setInfo->Data,
                dataSize);
        }

        CmCallbackReleaseKeyObjectIDEx(objectName);
        break;
    }

    /* ── Pre-delete value ─────────────────────────────────────────────── */
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION delInfo =
            (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;

        if (!delInfo || !delInfo->Object) {
            break;
        }

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegCookie, delInfo->Object, NULL, &objectName, 0);
        if (!NT_SUCCESS(status) || !objectName) {
            break;
        }

        if (!AkesoEDRRegistryIsNoisy(objectName)) {
            AkesoEDREmitRegistryEvent(
                AkesoEDRRegOpDeleteValue, objectName,
                delInfo->ValueName,
                0, NULL, 0);
        }

        CmCallbackReleaseKeyObjectIDEx(objectName);
        break;
    }

    /* ── Pre-delete key ───────────────────────────────────────────────── */
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION delKeyInfo =
            (PREG_DELETE_KEY_INFORMATION)Argument2;

        if (!delKeyInfo || !delKeyInfo->Object) {
            break;
        }

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegCookie, delKeyInfo->Object, NULL, &objectName, 0);
        if (!NT_SUCCESS(status) || !objectName) {
            break;
        }

        if (!AkesoEDRRegistryIsNoisy(objectName)) {
            AkesoEDREmitRegistryEvent(
                AkesoEDRRegOpDeleteKey, objectName,
                NULL, 0, NULL, 0);
        }

        CmCallbackReleaseKeyObjectIDEx(objectName);
        break;
    }

    /* ── Pre-rename key ───────────────────────────────────────────────── */
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION renameInfo =
            (PREG_RENAME_KEY_INFORMATION)Argument2;

        if (!renameInfo || !renameInfo->Object) {
            break;
        }

        status = CmCallbackGetKeyObjectIDEx(
            &g_RegCookie, renameInfo->Object, NULL, &objectName, 0);
        if (!NT_SUCCESS(status) || !objectName) {
            break;
        }

        if (!AkesoEDRRegistryIsNoisy(objectName)) {
            AkesoEDREmitRegistryEvent(
                AkesoEDRRegOpRenameKey, objectName,
                renameInfo->NewName,
                0, NULL, 0);
        }

        CmCallbackReleaseKeyObjectIDEx(objectName);
        break;
    }

    default:
        break;
    }

    /* Observe only — never block registry operations */
    return STATUS_SUCCESS;
}

/* ── Emit a registry telemetry event ───────────────────────────────────── */

static VOID
AkesoEDREmitRegistryEvent(
    _In_     AKESOEDR_REG_OP    Operation,
    _In_     PCUNICODE_STRING   KeyPath,
    _In_opt_ PCUNICODE_STRING   ValueName,
    _In_     ULONG              DataType,
    _In_opt_ PVOID              Data,
    _In_     ULONG              DataSize
)
{
    AKESOEDR_EVENT *event;
    HANDLE          pid = PsGetCurrentProcessId();

    event = (AKESOEDR_EVENT *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AKESOEDR_EVENT), AKESOEDR_TAG_EVENT);
    if (!event) {
        return;
    }

    __try {
        RtlZeroMemory(event, sizeof(AKESOEDR_EVENT));
        ExUuidCreate(&event->EventId);
        KeQuerySystemTimePrecise(&event->Timestamp);
        event->Source   = AkesoEDRSourceDriverRegistry;
        event->Severity = AkesoEDRSeverityInformational;

        /* Process context (who performed the registry operation) */
        AkesoEDRFillProcessCtxForRegistry(&event->ProcessCtx, pid);

        /* Registry payload */
        event->Payload.Registry.Operation = Operation;

        /* Key path */
        if (KeyPath && KeyPath->Buffer && KeyPath->Length > 0) {
            RtlStringCchCopyNW(
                event->Payload.Registry.KeyPath,
                AKESOEDR_MAX_PATH,
                KeyPath->Buffer,
                KeyPath->Length / sizeof(WCHAR));
        }

        /* Value name */
        if (ValueName && ValueName->Buffer && ValueName->Length > 0) {
            RtlStringCchCopyNW(
                event->Payload.Registry.ValueName,
                AKESOEDR_MAX_VALUE_NAME,
                ValueName->Buffer,
                ValueName->Length / sizeof(WCHAR));
        }

        /* Data (for SetValue) */
        event->Payload.Registry.DataType = DataType;
        if (Data && DataSize > 0) {
            ULONG copySize = DataSize;
            if (copySize > AKESOEDR_MAX_REG_DATA) {
                copySize = AKESOEDR_MAX_REG_DATA;
            }
            RtlCopyMemory(event->Payload.Registry.Data, Data, copySize);
            event->Payload.Registry.DataSize = copySize;
        }

        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "AkesoEDR: Registry op=%d PID=%lu key=%wZ\n",
            (int)Operation,
            (ULONG)(ULONG_PTR)pid,
            KeyPath));

        AkesoEDRCommsSend(event);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: Exception 0x%08X in registry callback PID=%lu\n",
            GetExceptionCode(),
            (ULONG)(ULONG_PTR)pid));
    }

    ExFreePoolWithTag(event, AKESOEDR_TAG_EVENT);
}

/* ── Helper: fill process context ──────────────────────────────────────── */

static VOID
AkesoEDRFillProcessCtxForRegistry(
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

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status) || !process) {
        return;
    }

    Ctx->ParentProcessId = (ULONG)(ULONG_PTR)
        PsGetProcessInheritedFromUniqueProcessId(process);

    {
        ULONG sessionId = 0;
        NTSTATUS sessionStatus = PsGetProcessSessionId(process, &sessionId);
        Ctx->SessionId = NT_SUCCESS(sessionStatus) ? sessionId : 0;
    }

    KeQuerySystemTimePrecise(&Ctx->ProcessCreateTime);

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
