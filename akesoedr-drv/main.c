/*
 * akesoedr-drv/main.c
 * AkesoEDR kernel-mode WDM driver — entry point and lifecycle.
 *
 * DriverEntry:
 *   1. Create device object + symbolic link
 *   2. Register minifilter (required for FltCreateCommunicationPort)
 *   3. Create filter communication port for agent connection
 *   4. Start minifilter filtering
 *
 * DriverUnload:
 *   Reverse all of the above in safe order.
 *
 * IRQL: DriverEntry and DriverUnload run at PASSIVE_LEVEL.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "constants.h"
#include "telemetry.h"
#include "comms.h"
#include "callbacks_process.h"
#include "callbacks_thread.h"
#include "callbacks_object.h"
#include "callbacks_imageload.h"
#include "callbacks_registry.h"
#include "kapc_inject.h"
#include "minifilter.h"
#include "minifilter_pipes.h"
#include "file_hash.h"
#include "wfp_callout.h"
#include "self_protect.h"

/* ── Forward declarations ────────────────────────────────────────────────── */

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     AkesoEDRUnload;

/* Minifilter unload callback */
NTSTATUS
AkesoEDRFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

/* Minifilter instance setup — accept all volumes for now */
NTSTATUS
AkesoEDRInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE              VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE      VolumeFilesystemType
);

/* ── Section placement ───────────────────────────────────────────────────── */

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AkesoEDRUnload)
#pragma alloc_text(PAGE, AkesoEDRFilterUnload)
#pragma alloc_text(PAGE, AkesoEDRInstanceSetup)
#endif

/* ── Globals ─────────────────────────────────────────────────────────────── */

PDEVICE_OBJECT  g_DeviceObject  = NULL;
PFLT_FILTER     g_FilterHandle  = NULL;

/* ── Minifilter registration structures ──────────────────────────────────── */

const FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {
    { FLT_CONTEXT_END }
};

/*
 * Minifilter I/O operation callbacks (Phase 5).
 * Pre-ops filter excluded paths; post-ops emit telemetry events.
 */
const FLT_OPERATION_REGISTRATION g_OperationCallbacks[] = {
    { IRP_MJ_CREATE,          0, AkesoEDRPreCreate,  AkesoEDRPostCreate },
    { IRP_MJ_WRITE,           0, AkesoEDRPreWrite,   AkesoEDRPostWrite },
    { IRP_MJ_SET_INFORMATION, 0, AkesoEDRPreSetInfo, AkesoEDRPostSetInfo },
    { IRP_MJ_CREATE_NAMED_PIPE, 0, AkesoEDRPreCreateNamedPipe, AkesoEDRPostCreateNamedPipe },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),               /* Size */
    FLT_REGISTRATION_VERSION,               /* Version */
    0,                                      /* Flags */
    g_ContextRegistration,                  /* Context */
    g_OperationCallbacks,                   /* OperationRegistration */
    AkesoEDRFilterUnload,                   /* FilterUnloadCallback */
    AkesoEDRInstanceSetup,                  /* InstanceSetupCallback */
    NULL,                                   /* InstanceQueryTeardownCallback */
    NULL,                                   /* InstanceTeardownStartCallback */
    NULL,                                   /* InstanceTeardownCompleteCallback */
    NULL, NULL, NULL                        /* GenerateFileName, NormalizeNameComponent, NormalizeContextCleanup */
};

/* ── Minifilter callbacks ────────────────────────────────────────────────── */

NTSTATUS
AkesoEDRFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    /* P11-T3: Stop self-protection monitor first */
    AkesoEDRSelfProtectShutdown();

    /* Unregister callbacks before tearing down comms (reverse init order) */
    AkesoEDRWfpStop();
    AkesoEDRFileHashStop();
    AkesoEDRKapcInjectStop();
    AkesoEDRRegistryCallbackStop();
    AkesoEDRImageLoadCallbackStop();
    AkesoEDRObjectCallbackStop();
    AkesoEDRThreadCallbackStop();
    AkesoEDRProcessCallbackStop();

    /* Teardown communication port */
    AkesoEDRCommsStop();

    /*
     * Do NOT call FltUnregisterFilter here — this callback is invoked
     * BY FltUnregisterFilter (from AkesoEDRUnload).  Re-calling it
     * would double-unregister and corrupt the filter manager.
     */

    return STATUS_SUCCESS;
}

NTSTATUS
AkesoEDRInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE              VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE      VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    /*
     * Log every volume attachment for diagnostics.
     * FLT_FSTYPE_NPFS = 8 — we need to confirm the minifilter
     * attaches to the Named Pipe File System.
     */
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "AkesoEDR: InstanceSetup devType=0x%X fsType=%d%s\n",
        (ULONG)VolumeDeviceType,
        (int)VolumeFilesystemType,
        (VolumeFilesystemType == FLT_FSTYPE_NPFS) ? " [NPFS!]" : ""));

    /* Accept all volumes including NPFS */
    return STATUS_SUCCESS;
}

/* ── DriverEntry ─────────────────────────────────────────────────────────── */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        status;
    UNICODE_STRING  deviceName;
    UNICODE_STRING  symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: DriverEntry v%s [minifilter+comms+callbacks]\n", AKESOEDR_VERSION));

    DriverObject->DriverUnload = AkesoEDRUnload;

    /* ── Step 1: Create device object ──────────────────────────────────── */

    RtlInitUnicodeString(&deviceName, AKESOEDR_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,                          /* DeviceExtensionSize */
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,                      /* Exclusive */
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: IoCreateDevice failed 0x%08X\n", status));
        return status;
    }

    /* ── Step 2: Create symbolic link ──────────────────────────────────── */

    RtlInitUnicodeString(&symlinkName, AKESOEDR_SYMLINK_NAME);

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: IoCreateSymbolicLink failed 0x%08X\n", status));
        goto cleanup_device;
    }

    /* ── Step 3: Register minifilter ───────────────────────────────────── */

    status = FltRegisterFilter(
        DriverObject,
        &g_FilterRegistration,
        &g_FilterHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: FltRegisterFilter failed 0x%08X\n", status));
        goto cleanup_symlink;
    }

    /* ── Step 4: Create communication port ─────────────────────────────── */

    status = AkesoEDRCommsInit(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRCommsInit failed 0x%08X\n", status));
        goto cleanup_filter;
    }

    /* ── Step 5: Register process callback (STUB) ─────────────────────── */

    status = AkesoEDRProcessCallbackInit();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRProcessCallbackInit failed 0x%08X\n", status));
        goto cleanup_comms;
    }

    /* ── Step 6: Register thread callback (STUB) ──────────────────────── */

    status = AkesoEDRThreadCallbackInit();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRThreadCallbackInit failed 0x%08X\n", status));
        goto cleanup_process_cb;
    }

    /* ── Step 7: Register object handle callbacks ────────────────────────── */

    status = AkesoEDRObjectCallbackInit();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRObjectCallbackInit failed 0x%08X\n", status));
        goto cleanup_thread_cb;
    }

    /* ── Step 8: Register image-load callback ─────────────────────────── */

    status = AkesoEDRImageLoadCallbackInit();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRImageLoadCallbackInit failed 0x%08X\n", status));
        goto cleanup_object_cb;
    }

    /* ── Step 9: Register registry callback ──────────────────────────── */

    status = AkesoEDRRegistryCallbackInit(DriverObject);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRRegistryCallbackInit failed 0x%08X\n", status));
        goto cleanup_imageload_cb;
    }

    /* ── Step 10: Initialize KAPC injection ──────────────────────────── */

    status = AkesoEDRKapcInjectInit();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRKapcInjectInit failed 0x%08X\n", status));
        goto cleanup_registry_cb;
    }

    /* ── Step 11: Initialize file hash subsystem ─────────────────────── */

    status = AkesoEDRFileHashInit();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRFileHashInit failed 0x%08X\n", status));
        goto cleanup_kapc;
    }

    /* ── Step 12: Initialize WFP callouts ─────────────────────────────── */

    status = AkesoEDRWfpInit(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRWfpInit failed 0x%08X\n", status));
        goto cleanup_hash;
    }

    /* ── Step 13: Self-protection monitoring (P11-T3) ─────────────────── */

    status = AkesoEDRSelfProtectInit();
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: AkesoEDRSelfProtectInit failed 0x%08X (non-fatal)\n", status));
        /* Non-fatal — continue without self-protection */
    }

    /* ── Step 14: Start filtering ──────────────────────────────────────── */

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: FltStartFiltering failed 0x%08X\n", status));
        goto cleanup_wfp;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Driver loaded successfully (stub callbacks)\n"));

    return STATUS_SUCCESS;

    /* ── Cleanup on failure ────────────────────────────────────────────── */

cleanup_wfp:
    AkesoEDRWfpStop();

cleanup_hash:
    AkesoEDRFileHashStop();

cleanup_kapc:
    AkesoEDRKapcInjectStop();

cleanup_registry_cb:
    AkesoEDRRegistryCallbackStop();

cleanup_imageload_cb:
    AkesoEDRImageLoadCallbackStop();

cleanup_object_cb:
    AkesoEDRObjectCallbackStop();

cleanup_thread_cb:
    AkesoEDRThreadCallbackStop();

cleanup_process_cb:
    AkesoEDRProcessCallbackStop();

cleanup_comms:
    AkesoEDRCommsStop();

cleanup_filter:
    FltUnregisterFilter(g_FilterHandle);
    g_FilterHandle = NULL;

cleanup_symlink:
    {
        UNICODE_STRING symName;
        RtlInitUnicodeString(&symName, AKESOEDR_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symName);
    }

cleanup_device:
    IoDeleteDevice(g_DeviceObject);
    g_DeviceObject = NULL;

    return status;
}

/* ── DriverUnload ────────────────────────────────────────────────────────── */

VOID
AkesoEDRUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: DriverUnload\n"));

    /* Unregister minifilter (triggers AkesoEDRFilterUnload which cleans up
       callbacks and comms) */
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    /* Delete symbolic link */
    {
        UNICODE_STRING symName;
        RtlInitUnicodeString(&symName, AKESOEDR_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symName);
    }

    /* Delete device object */
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Driver unloaded\n"));
}
