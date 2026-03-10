/*
 * sentinel-hook/hook_engine.h
 * x64 inline hook engine (Ch. 2 — custom mini-Detours).
 *
 * Patches the first bytes of a target function with an absolute JMP
 * to a detour, saves original bytes in an executable trampoline.
 * Calling the trampoline executes the original function.
 */

#ifndef SENTINEL_HOOK_ENGINE_H
#define SENTINEL_HOOK_ENGINE_H

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

#endif /* SENTINEL_HOOK_ENGINE_H */
