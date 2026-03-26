/*
 * akesoedr-hook/main.c
 * User-mode hooking DLL entry point (Ch. 2).
 *
 * Injected into target processes via KAPC (Phase 2).
 * Installs inline hooks on ntdll/kernel32 functions using the hook engine.
 *
 * P3-T1: Hook engine skeleton with Sleep test hook.
 * P3-T2: Core injection-detection hooks (NtAllocateVirtualMemory, etc.)
 * P3-T3: Remaining hooks + stack hash computation.
 * P3-T4: Named pipe client (ring buffer → agent pipe).
 */

#include <windows.h>
#include <stdio.h>
#include "hook_engine.h"
#include "hooks_common.h"
#include "pipe_client.h"
#include "evasion_detect.h"
#include "hook_integrity.h"

/* ── Hook installation ─────────────────────────────────────────────────────── */

static void
InstallAllHooks(void)
{
    HookEngineInit();

    /* P11-T1: Cache module ranges + ntdll .text CRC (pre-hook baseline) */
    AkesoEDREvasionInit();

    /* P3-T2: Core injection-detection hooks */
    InstallMemoryHooks();       /* NtAllocate/Protect/Write/ReadVirtualMemory */
    InstallThreadHooks();       /* NtCreateThreadEx, NtQueueApcThread, NtSuspend/ResumeThread */
    InstallSectionHooks();      /* NtMap/UnmapViewOfSection, NtCreateSection */

    /* P3-T3: Process hooks */
    InstallProcessHooks();      /* NtOpenProcess */

    /* P5-T3: Named pipe monitoring */
    InstallPipeHooks();         /* NtCreateNamedPipeFile */

    /* P11-T1: Recapture ntdll CRC after hooks are installed */
    AkesoEDREvasionRecaptureBaseline();

    /*
     * One-time init log. Uses _snprintf_s (CRT) + WriteFile (kernel32)
     * instead of wsprintfA (user32) + OutputDebugStringA (DBWIN mutex).
     * Both user32 and DBWIN are unsafe during early KAPC injection.
     */
    {
        char buf[256];
        DWORD written;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "AkesoEDRHook: PID=%lu hooks=%d ready\r\n",
                    GetCurrentProcessId(), HookEngineGetInstallCount());
        HANDLE hLog = CreateFileA("C:\\AkesoEDR\\hook_diag.log",
            FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hLog != INVALID_HANDLE_VALUE) {
            WriteFile(hLog, buf, (DWORD)lstrlenA(buf), &written, NULL);
            CloseHandle(hLog);
        }
    }
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
            AkesoEDRTlsInit();
            AkesoEDRPipeClientInit();
            InstallAllHooks();
            AkesoEDRHooksSetReady();
            /* P11-T2: Start hook integrity monitor (5s interval) */
            AkesoEDRHookIntegrityStart();
            break;

        case DLL_PROCESS_DETACH:
            AkesoEDRHookIntegrityStop();    /* P11-T2: Stop monitor first */
            RemoveAllInstalledHooks();
            AkesoEDRPipeClientShutdown();
            AkesoEDRTlsCleanup();
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
