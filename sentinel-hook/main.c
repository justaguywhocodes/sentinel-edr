/*
 * sentinel-hook/main.c
 * User-mode hooking DLL entry point (Ch. 2).
 *
 * Injected into target processes via KAPC (Phase 2).
 * Installs inline hooks on ntdll/kernel32 functions using the hook engine.
 *
 * P3-T1: Hook engine skeleton with Sleep test hook.
 * P3-T2: Core injection-detection hooks (NtAllocateVirtualMemory, etc.)
 * P3-T3: Remaining hooks + stack hash computation.
 */

#include <windows.h>
#include "hook_engine.h"
#include "hooks_common.h"

/* ── Hook installation ─────────────────────────────────────────────────────── */

static void
InstallAllHooks(void)
{
    char buf[256];

    HookEngineInit();

    /* P3-T2: Core injection-detection hooks */
    InstallMemoryHooks();       /* NtAllocate/Protect/Write/ReadVirtualMemory */
    InstallThreadHooks();       /* NtCreateThreadEx, NtQueueApcThread, NtSuspend/ResumeThread */
    InstallSectionHooks();      /* NtMap/UnmapViewOfSection, NtCreateSection */

    /* P3-T3: Process hooks */
    InstallProcessHooks();      /* NtOpenProcess */

    /* One-time init log — wsprintfA/OutputDebugStringA are safe here
       because hooks haven't been armed yet (g_HooksReady is FALSE). */
    wsprintfA(buf, "SentinelHook: PID=%lu hooks=%d ready\n",
              GetCurrentProcessId(), HookEngineGetInstallCount());
    OutputDebugStringA(buf);
}

static void
RemoveAllInstalledHooks(void)
{
    HookEngineCleanup();
}

/* ── DllMain ───────────────────────────────────────────────────────────────── */

BOOL APIENTRY
DllMain(
    HMODULE hModule,
    DWORD   dwReason,
    LPVOID  lpReserved
)
{
    (void)lpReserved;

    __try {
        switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            SentinelTlsInit();
            SentinelLogInit();
            InstallAllHooks();
            SentinelHooksSetReady();
            break;

        case DLL_PROCESS_DETACH:
            RemoveAllInstalledHooks();
            SentinelLogCleanup();
            SentinelTlsCleanup();
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Swallow exceptions — never crash the host process from DllMain */
        return TRUE;
    }

    return TRUE;
}
