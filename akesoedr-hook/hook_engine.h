/*
 * akesoedr-hook/hook_engine.h
 * x64 inline hook engine (Ch. 2 — custom mini-Detours).
 *
 * Patches the first bytes of a target function with an absolute JMP
 * to a detour, saves original bytes in an executable trampoline.
 * Calling the trampoline executes the original function.
 */

#ifndef AKESOEDR_HOOK_ENGINE_H
#define AKESOEDR_HOOK_ENGINE_H

#include <windows.h>

/*
 * HookEngineInit
 *   Initialize the hook engine. Call once from DLL_PROCESS_ATTACH.
 *   Returns TRUE on success.
 */
BOOL HookEngineInit(void);

/*
 * HookEngineCleanup
 *   Remove all hooks and free trampolines.
 *   Call from DLL_PROCESS_DETACH.
 */
void HookEngineCleanup(void);

/*
 * InstallHook
 *   Install an inline hook on a function.
 *
 *   ModuleName    — DLL containing the target (e.g., "ntdll.dll")
 *   FunctionName  — Export name (e.g., "NtAllocateVirtualMemory")
 *   DetourFunc    — Pointer to the replacement function
 *   OriginalFunc  — Receives pointer to the trampoline (call original)
 *
 *   Returns TRUE on success.
 */
BOOL InstallHook(
    const char *ModuleName,
    const char *FunctionName,
    void       *DetourFunc,
    void      **OriginalFunc
);

/*
 * RemoveHook
 *   Remove a previously installed hook by module + function name.
 *   Restores original bytes and frees the trampoline.
 *   Returns TRUE on success.
 */
BOOL RemoveHook(
    const char *ModuleName,
    const char *FunctionName
);

/*
 * RemoveAllHooks
 *   Remove all installed hooks. Called by HookEngineCleanup.
 */
void RemoveAllHooks(void);

/*
 * HookEngineGetInstallCount
 *   Returns the number of active hooks. Diagnostic use.
 */
int HookEngineGetInstallCount(void);

/*
 * P11-T2: Hook integrity support.
 */

/* Maximum number of hook slots (must match internal MAX_HOOKS) */
#define AKESOEDR_MAX_HOOKS  16

/*
 * AkesoEDRGetHookTarget
 *   Returns the target function address for hook slot 'index',
 *   or NULL if the slot is inactive. Used by integrity monitor.
 */
void *AkesoEDRGetHookTarget(int index);

/*
 * AkesoEDRGetHookName
 *   Returns the function name for hook slot 'index',
 *   or NULL if inactive.
 */
const char *AkesoEDRGetHookName(int index);

/*
 * AkesoEDRIsHookActive
 *   Returns TRUE if the hook slot 'index' is active.
 */
BOOL AkesoEDRIsHookActive(int index);

/*
 * AkesoEDRReinstallHook
 *   Re-patch the target function at slot 'index' with the JMP to detour.
 *   Used by hook integrity monitor to restore tampered hooks.
 *   Returns TRUE on success.
 */
BOOL AkesoEDRReinstallHook(int index);

#endif /* AKESOEDR_HOOK_ENGINE_H */
