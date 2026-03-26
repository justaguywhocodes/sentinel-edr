/*
 * akesoedr-agent/amsi/amsi_integrity.cpp
 * P11-T4: AMSI bypass detection.
 *
 * Captures the first 8 bytes of AmsiScanBuffer at startup and
 * periodically verifies they haven't been overwritten. The classic
 * AMSI bypass patches these bytes to:
 *   - 0xC3 (ret)                          — immediate return
 *   - 0xB8 0x57 0x00 0x07 0x80 0xC3       — mov eax, E_INVALIDARG; ret
 *
 * Detection emits an AKESOEDR_EVENT with Source = SelfProtect and
 * TamperType = AmsiPatched.
 */

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <thread>

#include "amsi_integrity.h"
#include "telemetry.h"
#include "constants.h"

/* ── Configuration ──────────────────────────────────────────────────────── */

static constexpr DWORD CHECK_INTERVAL_MS = 10000;  /* 10 seconds */
static constexpr int   BASELINE_SIZE     = 8;

/* ── State ──────────────────────────────────────────────────────────────── */

static HMODULE      g_hAmsi           = nullptr;
static BYTE*        g_pAmsiScanBuffer = nullptr;
static BYTE         g_Baseline[BASELINE_SIZE] = {};
static bool         g_Initialized     = false;

static HANDLE       g_hShutdownEvent  = nullptr;
static std::thread  g_MonitorThread;
static JsonWriter*  g_pWriter         = nullptr;

/* ── Tamper alert emission ──────────────────────────────────────────────── */

static void
EmitAmsiTamperAlert(const BYTE* oldBytes, const BYTE* newBytes)
{
    if (!g_pWriter)
        return;

    /* Build a tamper event */
    AKESOEDR_EVENT evt = {};
    evt.Source   = AkesoEDRSourceSelfProtect;
    evt.Severity = AkesoEDRSeverityHigh;

    /* Generate event ID */
    CoCreateGuid(&evt.EventId);

    /* Timestamp */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    evt.Timestamp.LowPart  = ft.dwLowDateTime;
    evt.Timestamp.HighPart = ft.dwHighDateTime;

    /* Fill tamper payload */
    evt.Payload.Tamper.TamperType = AkesoEDRTamperAmsiPatched;
    evt.Payload.Tamper.ProcessId  = GetCurrentProcessId();

    /* Format detail with old vs new bytes */
    char detail[256];
    _snprintf_s(detail, sizeof(detail), _TRUNCATE,
        "AmsiScanBuffer patched: was [%02X %02X %02X %02X %02X %02X %02X %02X] "
        "now [%02X %02X %02X %02X %02X %02X %02X %02X]",
        oldBytes[0], oldBytes[1], oldBytes[2], oldBytes[3],
        oldBytes[4], oldBytes[5], oldBytes[6], oldBytes[7],
        newBytes[0], newBytes[1], newBytes[2], newBytes[3],
        newBytes[4], newBytes[5], newBytes[6], newBytes[7]);

    MultiByteToWideChar(CP_ACP, 0, detail, -1,
                        evt.Payload.Tamper.Detail, AKESOEDR_MAX_PATH);

    /* Write to JSON log */
    g_pWriter->WriteEvent(evt, L"");

    std::printf("AkesoEDRAgent: AMSI TAMPER DETECTED: %s\n", detail);
}

/* ── Monitor thread ─────────────────────────────────────────────────────── */

static void
MonitorThread()
{
    while (WaitForSingleObject(g_hShutdownEvent, CHECK_INTERVAL_MS)
           == WAIT_TIMEOUT) {

        if (!g_pAmsiScanBuffer)
            continue;

        /* Compare current bytes against baseline */
        BYTE current[BASELINE_SIZE];
        memcpy(current, g_pAmsiScanBuffer, BASELINE_SIZE);

        if (memcmp(current, g_Baseline, BASELINE_SIZE) != 0) {
            EmitAmsiTamperAlert(g_Baseline, current);

            /* Update baseline to avoid re-alerting every 10s.
             * The patch is already in place — one alert is enough. */
            memcpy(g_Baseline, current, BASELINE_SIZE);
        }
    }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void
AmsiIntegrityInit(JsonWriter* writer)
{
    g_pWriter = writer;

    /* Load amsi.dll (should already be loaded by AMSI registration) */
    g_hAmsi = LoadLibraryW(L"amsi.dll");
    if (!g_hAmsi) {
        std::printf("AkesoEDRAgent: AMSI integrity: amsi.dll not loaded "
                    "(AMSI monitoring disabled)\n");
        return;
    }

    /* Resolve AmsiScanBuffer */
    g_pAmsiScanBuffer = (BYTE*)GetProcAddress(g_hAmsi, "AmsiScanBuffer");
    if (!g_pAmsiScanBuffer) {
        std::printf("AkesoEDRAgent: AMSI integrity: AmsiScanBuffer not found\n");
        FreeLibrary(g_hAmsi);
        g_hAmsi = nullptr;
        return;
    }

    /* Capture baseline */
    memcpy(g_Baseline, g_pAmsiScanBuffer, BASELINE_SIZE);

    std::printf("AkesoEDRAgent: AMSI integrity monitor started "
                "(baseline: %02X %02X %02X %02X %02X %02X %02X %02X)\n",
                g_Baseline[0], g_Baseline[1], g_Baseline[2], g_Baseline[3],
                g_Baseline[4], g_Baseline[5], g_Baseline[6], g_Baseline[7]);

    /* Start monitor thread */
    g_hShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_MonitorThread = std::thread(MonitorThread);
    g_Initialized = true;
}

void
AmsiIntegrityShutdown()
{
    if (!g_Initialized)
        return;

    SetEvent(g_hShutdownEvent);
    if (g_MonitorThread.joinable())
        g_MonitorThread.join();

    CloseHandle(g_hShutdownEvent);
    g_hShutdownEvent = nullptr;

    if (g_hAmsi) {
        FreeLibrary(g_hAmsi);
        g_hAmsi = nullptr;
    }

    g_pAmsiScanBuffer = nullptr;
    g_Initialized = false;
}
