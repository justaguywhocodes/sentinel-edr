/*
 * sentinel-agent/service.cpp
 * Windows service control handler and lifecycle management.
 *
 * Implements ServiceMain (registered with SCM) and the service control
 * handler for start/stop. Console mode is provided for debugging without
 * the SCM.
 */

#include <windows.h>
#include <cstdio>
#include "service.h"
#include "pipeline.h"
#include "constants.h"

/* ── Service state ────────────────────────────────────────────────────────── */

static SERVICE_STATUS        g_ServiceStatus    = {};
static SERVICE_STATUS_HANDLE g_StatusHandle     = nullptr;
static HANDLE                g_StopEvent        = nullptr;

/* ── Status reporting ─────────────────────────────────────────────────────── */

static void
ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;

    g_ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState            = currentState;
    g_ServiceStatus.dwWin32ExitCode           = exitCode;
    g_ServiceStatus.dwWaitHint                = waitHint;

    if (currentState == SERVICE_START_PENDING) {
        g_ServiceStatus.dwControlsAccepted = 0;
    } else {
        g_ServiceStatus.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        g_ServiceStatus.dwCheckPoint = 0;
    } else {
        g_ServiceStatus.dwCheckPoint = checkPoint++;
    }

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/* ── Service control handler ──────────────────────────────────────────────── */

static DWORD WINAPI
ServiceCtrlHandler(
    DWORD   control,
    DWORD   eventType,
    LPVOID  eventData,
    LPVOID  context)
{
    (void)eventType;
    (void)eventData;
    (void)context;

    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        SetEvent(g_StopEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* ── ServiceMain ──────────────────────────────────────────────────────────── */

void WINAPI
ServiceMain(DWORD argc, LPWSTR* argv)
{
    (void)argc;
    (void)argv;

    /* Register the control handler */
    g_StatusHandle = RegisterServiceCtrlHandlerExW(
        SENTINEL_AGENT_SERVICE,
        ServiceCtrlHandler,
        nullptr);

    if (g_StatusHandle == nullptr) {
        return;
    }

    /* Report start pending */
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    /* Create the stop event */
    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_StopEvent == nullptr) {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    /* Start the event pipeline */
    PipelineStart();

    /* Report running */
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    /* Wait for stop signal */
    WaitForSingleObject(g_StopEvent, INFINITE);

    /* Shut down the pipeline */
    PipelineStop();

    CloseHandle(g_StopEvent);
    g_StopEvent = nullptr;

    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

/* ── Console mode ─────────────────────────────────────────────────────────── */

static HANDLE g_ConsoleStopEvent = nullptr;

static BOOL WINAPI
ConsoleCtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        std::printf("\nSentinelAgent: Shutting down...\n");
        if (g_ConsoleStopEvent != nullptr) {
            SetEvent(g_ConsoleStopEvent);
        }
        return TRUE;
    }
    return FALSE;
}

void
RunConsoleMode()
{
    std::printf("SentinelAgent: Running in console mode (Ctrl+C to stop)\n");

    g_ConsoleStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    /* Start the pipeline */
    PipelineStart();

    std::printf("SentinelAgent: Pipeline started, waiting for events...\n");

    /* Wait for Ctrl+C */
    WaitForSingleObject(g_ConsoleStopEvent, INFINITE);

    /* Shut down */
    PipelineStop();

    CloseHandle(g_ConsoleStopEvent);
    g_ConsoleStopEvent = nullptr;

    std::printf("SentinelAgent: Stopped.\n");
}
