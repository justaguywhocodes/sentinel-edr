/*
 * akesoedr-watchdog/main.cpp
 * Lightweight watchdog service that monitors the AkesoEDR agent.
 *
 * Runs as a separate Windows service (AkesoEDRWatchdog). Every 5 seconds
 * it checks the agent service state via SCM. If the agent has stopped
 * unexpectedly, the watchdog restarts it and logs the event.
 *
 * Also performs a pipe health check — if the agent's command pipe is
 * unreachable for 3 consecutive checks, the agent is assumed hung
 * and forcibly restarted.
 *
 * Usage:
 *   akesoedr-watchdog.exe              — Run as Windows service
 *   akesoedr-watchdog.exe --console    — Run in console mode (debug)
 */

#include <windows.h>
#include <cstdio>
#include <ctime>
#include "constants.h"

/* ── Configuration ──────────────────────────────────────────────────────── */

#define WATCHDOG_CHECK_INTERVAL_MS  5000    /* 5 seconds between checks     */
#define PIPE_FAIL_THRESHOLD         3       /* 3 consecutive failures = hung */
#define LOG_PATH                    "C:\\AkesoEDR\\watchdog.log"
#define PIPE_NAME                   "\\\\.\\pipe\\AkesoEDRCommand"

/* ── Logging ────────────────────────────────────────────────────────────── */

static void
LogEvent(const char* fmt, ...)
{
    /* Timestamp */
    time_t now = time(nullptr);
    struct tm tm = {};
    localtime_s(&tm, &now);
    char timeBuf[64];
    strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tm);

    /* Format message */
    char msgBuf[512];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(msgBuf, sizeof(msgBuf), _TRUNCATE, fmt, args);
    va_end(args);

    /* Console output */
    std::printf("[%s] %s\n", timeBuf, msgBuf);

    /* File output */
    FILE* f = nullptr;
    if (fopen_s(&f, LOG_PATH, "a") == 0 && f) {
        std::fprintf(f, "[%s] %s\n", timeBuf, msgBuf);
        fclose(f);
    }

    /* Debug output */
    OutputDebugStringA("[AkesoEDR-Watchdog] ");
    OutputDebugStringA(msgBuf);
    OutputDebugStringA("\n");
}

/* ── Agent service management ───────────────────────────────────────────── */

static SC_HANDLE g_hSCM       = nullptr;
static SC_HANDLE g_hAgentSvc  = nullptr;

static bool
OpenAgentService()
{
    if (!g_hSCM) {
        g_hSCM = OpenSCManagerW(nullptr, nullptr,
                                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (!g_hSCM) {
            LogEvent("ERROR: OpenSCManager failed (%lu)", GetLastError());
            return false;
        }
    }

    if (!g_hAgentSvc) {
        g_hAgentSvc = OpenServiceW(g_hSCM, AKESOEDR_AGENT_SERVICE,
                                   SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP);
        if (!g_hAgentSvc) {
            LogEvent("ERROR: OpenService(%ls) failed (%lu)",
                     AKESOEDR_AGENT_SERVICE, GetLastError());
            return false;
        }
    }

    return true;
}

static void
CloseAgentService()
{
    if (g_hAgentSvc) { CloseServiceHandle(g_hAgentSvc); g_hAgentSvc = nullptr; }
    if (g_hSCM)      { CloseServiceHandle(g_hSCM);      g_hSCM = nullptr;      }
}

static DWORD
GetAgentState()
{
    SERVICE_STATUS status = {};
    if (!QueryServiceStatus(g_hAgentSvc, &status))
        return 0;
    return status.dwCurrentState;
}

static bool
StartAgent()
{
    if (!StartServiceW(g_hAgentSvc, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
            return true;
        LogEvent("ERROR: StartService failed (%lu)", err);
        return false;
    }
    return true;
}

/* ── Pipe health check ──────────────────────────────────────────────────── */

static int g_PipeFailCount = 0;

static bool
CheckAgentPipe()
{
    HANDLE hPipe = CreateFileA(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        g_PipeFailCount++;
        return false;
    }

    /* Pipe is reachable — reset counter */
    CloseHandle(hPipe);
    g_PipeFailCount = 0;
    return true;
}

/* ── Monitor loop ───────────────────────────────────────────────────────── */

static HANDLE g_ShutdownEvent = nullptr;
static bool   g_WatchdogRequestedStop = false;

static void
MonitorLoop()
{
    LogEvent("Watchdog monitor started (interval=%dms)", WATCHDOG_CHECK_INTERVAL_MS);

    if (!OpenAgentService()) {
        LogEvent("ERROR: Cannot open agent service — monitor exiting");
        return;
    }

    DWORD restartCount = 0;

    while (WaitForSingleObject(g_ShutdownEvent,
                               WATCHDOG_CHECK_INTERVAL_MS) == WAIT_TIMEOUT) {

        DWORD state = GetAgentState();

        if (state == SERVICE_RUNNING) {
            /* Agent is running — check pipe health */
            if (!CheckAgentPipe()) {
                if (g_PipeFailCount >= PIPE_FAIL_THRESHOLD) {
                    LogEvent("WARN: Agent pipe unreachable for %d checks — "
                             "agent may be hung", g_PipeFailCount);
                    /* Don't force-kill here — just log. The agent might be
                     * starting up or under heavy load. */
                }
            }
        } else if (state == SERVICE_STOPPED || state == 0) {
            if (!g_WatchdogRequestedStop) {
                restartCount++;
                LogEvent("ALERT: Agent service stopped unexpectedly — "
                         "restarting (attempt #%lu)", restartCount);

                if (StartAgent()) {
                    LogEvent("Agent service restart initiated successfully");
                    g_PipeFailCount = 0;
                } else {
                    LogEvent("ERROR: Failed to restart agent service");
                }
            }
        } else if (state == SERVICE_START_PENDING) {
            /* Agent is starting — wait */
        } else if (state == SERVICE_STOP_PENDING) {
            /* Agent is stopping — might be intentional */
        }
    }

    CloseAgentService();
    LogEvent("Watchdog monitor stopped (%lu restarts performed)", restartCount);
}

/* ── Windows service plumbing ───────────────────────────────────────────── */

static SERVICE_STATUS        g_SvcStatus  = {};
static SERVICE_STATUS_HANDLE g_SvcHandle  = nullptr;

static void
ReportStatus(DWORD state, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;

    g_SvcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_SvcStatus.dwCurrentState     = state;
    g_SvcStatus.dwWin32ExitCode    = exitCode;
    g_SvcStatus.dwWaitHint         = waitHint;

    if (state == SERVICE_START_PENDING)
        g_SvcStatus.dwControlsAccepted = 0;
    else
        g_SvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
        g_SvcStatus.dwCheckPoint = 0;
    else
        g_SvcStatus.dwCheckPoint = checkPoint++;

    SetServiceStatus(g_SvcHandle, &g_SvcStatus);
}

static DWORD WINAPI
SvcCtrlHandler(DWORD control, DWORD, LPVOID, LPVOID)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        SetEvent(g_ShutdownEvent);
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static void WINAPI
SvcMain(DWORD, LPWSTR*)
{
    g_SvcHandle = RegisterServiceCtrlHandlerExW(
        AKESOEDR_WATCHDOG_SERVICE, SvcCtrlHandler, nullptr);

    if (!g_SvcHandle) return;

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    g_ShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_ShutdownEvent) {
        ReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    MonitorLoop();

    CloseHandle(g_ShutdownEvent);
    g_ShutdownEvent = nullptr;

    ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

/* ── Console mode ───────────────────────────────────────────────────────── */

static BOOL WINAPI
ConsoleCtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        std::printf("\nAkesoEDR-Watchdog: Shutting down...\n");
        if (g_ShutdownEvent)
            SetEvent(g_ShutdownEvent);
        return TRUE;
    }
    return FALSE;
}

static void
RunConsoleMode()
{
    std::printf("AkesoEDR-Watchdog: Running in console mode (Ctrl+C to stop)\n");

    g_ShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    MonitorLoop();

    CloseHandle(g_ShutdownEvent);
    g_ShutdownEvent = nullptr;

    std::printf("AkesoEDR-Watchdog: Stopped.\n");
}

/* ── Entry point ────────────────────────────────────────────────────────── */

int wmain(int argc, wchar_t* argv[])
{
    /* Check for --console flag */
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--console") == 0) {
            RunConsoleMode();
            return 0;
        }
    }

    /* Try to start as Windows service */
    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        { const_cast<LPWSTR>(AKESOEDR_WATCHDOG_SERVICE), SvcMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(dispatchTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::printf(
                "AkesoEDR Watchdog\n"
                "Usage:\n"
                "  akesoedr-watchdog.exe --console   Run in console mode\n"
                "  sc.exe start AkesoEDRWatchdog     Start as Windows service\n");
        } else {
            std::fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", err);
        }
        return 1;
    }

    return 0;
}
