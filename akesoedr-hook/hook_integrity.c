/*
 * akesoedr-hook/hook_integrity.c
 * P11-T2: Hook integrity monitoring with automatic re-installation.
 *
 * A background thread wakes every 5 seconds and verifies that all
 * installed inline hooks are still intact by checking the first 2 bytes
 * of each hooked function (should be 0x48 0xB8 — the MOV RAX, imm64
 * prologue of our absolute JMP patch).
 *
 * If a hook is found to be tampered (bytes changed), the monitor:
 *   1. Emits a tamper alert via the ring buffer
 *   2. Re-installs the hook (rebuilds the JMP patch)
 *
 * Also calls AkesoEDRVerifyNtdllIntegrity() to detect full ntdll
 * remapping (fresh copy mapped from disk to bypass all hooks).
 */

#include <windows.h>
#include <stdio.h>
#include "hook_engine.h"
#include "hook_integrity.h"
#include "hooks_common.h"
#include "evasion_detect.h"

/* ── Configuration ─────────────────────────────────────────────────────── */

#define INTEGRITY_CHECK_INTERVAL_MS     5000    /* 5 seconds */

/* ── State ─────────────────────────────────────────────────────────────── */

static HANDLE   g_hIntegrityThread  = NULL;
static HANDLE   g_hShutdownEvent    = NULL;

/* ── JMP patch signature ───────────────────────────────────────────────── */

/* Our hook JMP patch starts with: 48 B8 (MOV RAX, imm64) */
#define JMP_PATCH_BYTE0     0x48
#define JMP_PATCH_BYTE1     0xB8

/* ── Tamper alert emission ─────────────────────────────────────────────── */

static void
EmitTamperAlert(const char *funcName, const char *detail)
{
    if (!AkesoEDRHooksAreReady())
        return;

    if (!AkesoEDREnterHook())
        return;

    AKESOEDR_HOOK_EVENT evt = {0};
    evt.Function        = AkesoEDRHookNtAllocateVirtualMemory; /* placeholder */
    evt.TargetProcessId = 0;
    evt.Protection      = 0xDEAD;   /* Sentinel value for tamper events */
    evt.EvasionFlags    = AKESOEDR_EVASION_NTDLL_REMAP;

    /* Put the tampered function name in CallingModule for identification */
    if (funcName) {
        MultiByteToWideChar(CP_ACP, 0, funcName, -1,
                            evt.CallingModule, AKESOEDR_MAX_MODULE_NAME);
    }

    AkesoEDREmitHookEvent(&evt);
    AkesoEDRLeaveHook();
}

/* ── Integrity check worker ────────────────────────────────────────────── */

static DWORD WINAPI
IntegrityCheckThread(LPVOID param)
{
    (void)param;

    while (WaitForSingleObject(g_hShutdownEvent,
                               INTEGRITY_CHECK_INTERVAL_MS) == WAIT_TIMEOUT) {
        int tamperedCount = 0;

        /* Check each hook slot */
        for (int i = 0; i < AKESOEDR_MAX_HOOKS; i++) {
            if (!AkesoEDRIsHookActive(i))
                continue;

            void *target = AkesoEDRGetHookTarget(i);
            if (!target)
                continue;

            /* Verify the first 2 bytes match our JMP patch signature */
            BYTE *code = (BYTE *)target;
            if (code[0] != JMP_PATCH_BYTE0 || code[1] != JMP_PATCH_BYTE1) {
                /* Hook has been tampered! */
                const char *name = AkesoEDRGetHookName(i);
                EmitTamperAlert(name, "Hook bytes overwritten");

                /* Re-install the hook */
                AkesoEDRReinstallHook(i);
                tamperedCount++;
            }
        }

        /* Also check ntdll .text integrity (detects full remap) */
        if (!AkesoEDRVerifyNtdllIntegrity()) {
            EmitTamperAlert("ntdll.dll", "ntdll .text section modified (remap?)");

            /* If ntdll was remapped, ALL hooks are gone — re-install all */
            for (int i = 0; i < AKESOEDR_MAX_HOOKS; i++) {
                if (AkesoEDRIsHookActive(i)) {
                    AkesoEDRReinstallHook(i);
                }
            }

            /* Recapture baseline after re-install */
            AkesoEDREvasionRecaptureBaseline();
        }
    }

    return 0;
}

/* ── Public API ────────────────────────────────────────────────────────── */

void
AkesoEDRHookIntegrityStart(void)
{
    g_hShutdownEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hShutdownEvent)
        return;

    g_hIntegrityThread = CreateThread(NULL, 0, IntegrityCheckThread, NULL, 0, NULL);
}

void
AkesoEDRHookIntegrityStop(void)
{
    if (g_hShutdownEvent)
        SetEvent(g_hShutdownEvent);

    if (g_hIntegrityThread) {
        WaitForSingleObject(g_hIntegrityThread, 2000);
        CloseHandle(g_hIntegrityThread);
        g_hIntegrityThread = NULL;
    }

    if (g_hShutdownEvent) {
        CloseHandle(g_hShutdownEvent);
        g_hShutdownEvent = NULL;
    }
}
