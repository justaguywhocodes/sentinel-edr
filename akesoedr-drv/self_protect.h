/*
 * akesoedr-drv/self_protect.h
 * P11-T3: Kernel callback tamper detection + ETW heartbeat monitoring.
 *
 * Runs a background system thread that verifies driver callbacks are still
 * active by monitoring canary counters (incremented in each callback).
 * If a counter stops incrementing, the callback was likely removed by
 * an attacker. Also monitors agent heartbeats to detect ETW session kills.
 */

#ifndef AKESOEDR_SELF_PROTECT_H
#define AKESOEDR_SELF_PROTECT_H

#include <fltKernel.h>

/*
 * AkesoEDRSelfProtectInit
 *   Start the self-protection monitoring thread.
 *   Call from DriverEntry after all callbacks are registered.
 *   Returns STATUS_SUCCESS or an error code.
 */
NTSTATUS AkesoEDRSelfProtectInit(void);

/*
 * AkesoEDRSelfProtectShutdown
 *   Stop the monitoring thread and clean up.
 *   Call from AkesoEDRFilterUnload before unregistering callbacks.
 */
void AkesoEDRSelfProtectShutdown(void);

/*
 * AkesoEDRSelfProtectHeartbeat
 *   Called when the agent sends a heartbeat via the filter port.
 *   Updates the last-seen timestamp for ETW session monitoring.
 */
void AkesoEDRSelfProtectHeartbeat(void);

/*
 * Canary counter increments — called from each callback.
 * These are lock-free (InterlockedIncrement) and safe at any IRQL.
 */
void AkesoEDRCanaryProcessCallback(void);
void AkesoEDRCanaryRegistryCallback(void);
void AkesoEDRCanaryImageLoadCallback(void);
void AkesoEDRCanaryMinifilterCallback(void);

#endif /* AKESOEDR_SELF_PROTECT_H */
