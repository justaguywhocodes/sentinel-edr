/*
 * sentinel-drv/callbacks_registry.h
 * Registry callback registration (Ch. 5 — CmRegisterCallbackEx).
 *
 * Monitors key create, value set/delete, key delete, and key rename.
 * Emits telemetry events with full key path, value name, and data.
 */

#ifndef SENTINEL_CALLBACKS_REGISTRY_H
#define SENTINEL_CALLBACKS_REGISTRY_H

#include <fltKernel.h>

/*
 * Register registry callback via CmRegisterCallbackEx.
 * Call from DriverEntry after image-load callback is initialized.
 *
 * DriverObject is required by CmRegisterCallbackEx for altitude.
 */
NTSTATUS
SentinelRegistryCallbackInit(
    _In_ PDRIVER_OBJECT DriverObject
);

/*
 * Unregister registry callback.
 * Call from DriverUnload / FilterUnload.
 * Safe to call if Init was never called or already stopped.
 */
VOID
SentinelRegistryCallbackStop(VOID);

#endif /* SENTINEL_CALLBACKS_REGISTRY_H */
