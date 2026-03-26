/*
 * akesoedr-hook/hook_integrity.h
 * P11-T2: Hook integrity monitoring.
 *
 * Background thread that verifies all installed inline hooks every 5 seconds.
 * If a hook has been removed or overwritten (e.g., by ntdll unhooking),
 * it emits a tamper alert and re-installs the hook.
 */

#ifndef AKESOEDR_HOOK_INTEGRITY_H
#define AKESOEDR_HOOK_INTEGRITY_H

#include <windows.h>

/*
 * AkesoEDRHookIntegrityStart
 *   Launch the integrity monitoring background thread.
 *   Call AFTER AkesoEDRHooksSetReady() in DllMain.
 *   Safe to call from DLL_PROCESS_ATTACH — uses CreateThread
 *   which is deferred until after DllMain returns.
 */
void AkesoEDRHookIntegrityStart(void);

/*
 * AkesoEDRHookIntegrityStop
 *   Signal the monitor thread to stop and wait for it to exit.
 *   Call BEFORE RemoveAllHooks in DLL_PROCESS_DETACH.
 */
void AkesoEDRHookIntegrityStop(void);

#endif /* AKESOEDR_HOOK_INTEGRITY_H */
