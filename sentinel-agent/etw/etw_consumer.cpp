/*
 * sentinel-agent/etw/etw_consumer.cpp
 * ETW (Event Tracing for Windows) consumer framework implementation.
 *
 * Creates a real-time trace session, enables ETW providers, and runs a
 * consumer thread that converts events into SENTINEL_EVENT telemetry.
 *
 * Architecture:
 *   StartTrace → EnableTraceEx2 (per provider)
 *   Consumer thread: OpenTrace → ProcessTrace (blocks) → CloseTrace
 *   Event callback: dispatch to provider parser → push to EventQueue
 *
 * P7-T1: ETW Consumer Framework + .NET Provider.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

/*
 * INITGUID must be defined before <guiddef.h> / <windows.h> so that
 * DEFINE_GUID in constants.h emits storage rather than an extern reference.
 */
#define INITGUID

#include "etw_consumer.h"
#include "provider_dotnet.h"
#include "provider_dns.h"
#include "provider_powershell.h"
#include "provider_kerberos.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <atomic>

#include "telemetry.h"
#include "constants.h"
#include "pipeline.h"

/* ── Constants ──────────────────────────────────────────────────────────── */

#define ETW_SESSION_NAME    L"SentinelEtwSession"

/*
 * .NET Runtime keywords for assembly load events:
 *   LoaderKeyword        = 0x8   (legacy event IDs 154/155)
 *   AssemblyLoaderKeyword= 0x4   (CoreCLR event ID 290 — .NET 6+)
 * Both are enabled to cover .NET Framework and CoreCLR runtimes.
 */
#define DOTNET_LOADER_KEYWORD   (0x8ULL | 0x4ULL)

/* ── State ──────────────────────────────────────────────────────────────── */

static TRACEHANDLE              s_SessionHandle = 0;
static TRACEHANDLE              s_ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
static std::thread              s_ConsumerThread;
static std::atomic<bool>        s_Initialized{false};

/*
 * Properties buffer: EVENT_TRACE_PROPERTIES followed by the session name.
 * Must be contiguous in memory.
 */
static BYTE s_PropertiesBuf[sizeof(EVENT_TRACE_PROPERTIES) + 256 * sizeof(WCHAR)];

/* ── Forward declarations ───────────────────────────────────────────────── */

static void WINAPI EtwEventCallback(PEVENT_RECORD pEvent);
static void EtwConsumerThreadFunc();

/* ── Extern access to pipeline globals ──────────────────────────────────── */

/*
 * g_EventQueue and g_Shutdown are defined in pipeline.cpp.
 * They are exposed as extern in pipeline.h for sub-components
 * (like this ETW consumer) that need to push events.
 */

/* ── Helper: set up properties structure ─────────────────────────────────── */

static EVENT_TRACE_PROPERTIES*
BuildProperties()
{
    memset(s_PropertiesBuf, 0, sizeof(s_PropertiesBuf));

    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(s_PropertiesBuf);
    props->Wnode.BufferSize    = sizeof(s_PropertiesBuf);
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;  /* QPC timestamps */
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    return props;
}

/* ── EtwConsumerInit ────────────────────────────────────────────────────── */

bool
EtwConsumerInit()
{
    ULONG status;

    std::printf("SentinelAgent: ETW consumer initializing...\n");

    /* ── Step 1: Clean up stale session from a previous crash ─────── */

    {
        auto* props = BuildProperties();
        status = ControlTraceW(
            0, ETW_SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);

        if (status == ERROR_SUCCESS) {
            std::printf("SentinelAgent: Cleaned up stale ETW session\n");
        }
        /* ERROR_WMI_INSTANCE_NOT_FOUND means no stale session — OK */
    }

    /* ── Step 2: Create the real-time trace session ──────────────── */

    {
        auto* props = BuildProperties();

        status = StartTraceW(&s_SessionHandle, ETW_SESSION_NAME, props);
        if (status != ERROR_SUCCESS) {
            std::printf("SentinelAgent: StartTraceW failed (error %lu)\n", status);
            if (status == ERROR_ACCESS_DENIED) {
                std::printf("SentinelAgent: ETW requires administrator privileges\n");
            }
            return false;
        }
    }

    std::printf("SentinelAgent: ETW trace session created (handle=%llu)\n",
        (unsigned long long)s_SessionHandle);

    /* ── Step 3: Enable .NET Runtime provider ────────────────────── */

    status = EnableTraceEx2(
        s_SessionHandle,
        &SENTINEL_ETW_DOTNET_RUNTIME,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,        /* Level 5 — CoreCLR fires some events here */
        DOTNET_LOADER_KEYWORD,      /* MatchAnyKeyword: LoaderKeyword | AssemblyLoaderKeyword */
        0,                          /* MatchAllKeyword */
        0,                          /* Timeout (0 = async) */
        NULL                        /* EnableParameters */
    );

    if (status != ERROR_SUCCESS) {
        std::printf("SentinelAgent: EnableTraceEx2 (DotNet) failed (error %lu)\n",
            status);
        /* Non-fatal — session exists, just no DotNet events */
    } else {
        std::printf("SentinelAgent: Enabled provider: Microsoft-Windows-DotNETRuntime\n");
    }

    /* ── Step 4: Enable DNS Client provider ──────────────────────── */

    status = EnableTraceEx2(
        s_SessionHandle,
        &SENTINEL_ETW_DNS_CLIENT,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,    /* Level 4 — DNS events fire here */
        0,                          /* MatchAnyKeyword: 0 = all; parser filters by event ID */
        0,                          /* MatchAllKeyword */
        0,                          /* Timeout (0 = async) */
        NULL                        /* EnableParameters */
    );

    if (status != ERROR_SUCCESS) {
        std::printf("SentinelAgent: EnableTraceEx2 (DNS) failed (error %lu)\n",
            status);
    } else {
        std::printf("SentinelAgent: Enabled provider: Microsoft-Windows-DNS-Client\n");
    }

    /* ── Step 5: Enable PowerShell provider ──────────────────────── */

    status = EnableTraceEx2(
        s_SessionHandle,
        &SENTINEL_ETW_POWERSHELL,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,        /* Level 5 — script block events fire at Verbose */
        0,                          /* MatchAnyKeyword: 0 = all; parser filters by event ID */
        0,                          /* MatchAllKeyword */
        0,                          /* Timeout (0 = async) */
        NULL                        /* EnableParameters */
    );

    if (status != ERROR_SUCCESS) {
        std::printf("SentinelAgent: EnableTraceEx2 (PowerShell) failed (error %lu)\n",
            status);
    } else {
        std::printf("SentinelAgent: Enabled provider: Microsoft-Windows-PowerShell\n");
    }

    /* ── Step 6: Enable Kerberos provider ────────────────────────── */

    status = EnableTraceEx2(
        s_SessionHandle,
        &SENTINEL_ETW_KERBEROS,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,    /* Level 4 — ticket events fire here */
        0,                          /* MatchAnyKeyword: 0 = all; parser filters by event ID */
        0,                          /* MatchAllKeyword */
        0,                          /* Timeout (0 = async) */
        NULL                        /* EnableParameters */
    );

    if (status != ERROR_SUCCESS) {
        std::printf("SentinelAgent: EnableTraceEx2 (Kerberos) failed (error %lu)\n",
            status);
    } else {
        std::printf("SentinelAgent: Enabled provider: Microsoft-Windows-Security-Kerberos\n");
    }

    s_Initialized.store(true);
    return true;
}

/* ── EtwConsumerStart ───────────────────────────────────────────────────── */

void
EtwConsumerStart()
{
    if (!s_Initialized.load()) {
        return;
    }

    s_ConsumerThread = std::thread(EtwConsumerThreadFunc);

    std::printf("SentinelAgent: ETW consumer thread started\n");
}

/* ── EtwConsumerStop ────────────────────────────────────────────────────── */

void
EtwConsumerStop()
{
    if (!s_Initialized.load()) {
        return;
    }

    s_Initialized.store(false);

    std::printf("SentinelAgent: ETW consumer stopping...\n");

    /* Stop the trace session — this unblocks ProcessTrace() */
    {
        auto* props = BuildProperties();
        ULONG status = ControlTraceW(
            s_SessionHandle, NULL, props, EVENT_TRACE_CONTROL_STOP);

        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            std::printf("SentinelAgent: ControlTrace STOP failed (error %lu)\n",
                status);
        }
    }

    /* Close the consumer trace handle if open */
    if (s_ConsumerHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(s_ConsumerHandle);
        s_ConsumerHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    /* Join the consumer thread */
    if (s_ConsumerThread.joinable()) {
        s_ConsumerThread.join();
    }

    s_SessionHandle = 0;

    std::printf("SentinelAgent: ETW consumer stopped\n");
}

/* ── Consumer thread function ───────────────────────────────────────────── */

static void
EtwConsumerThreadFunc()
{
    EVENT_TRACE_LOGFILEW logFile = {};

    logFile.LoggerName          = const_cast<LPWSTR>(ETW_SESSION_NAME);
    logFile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME
                                | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwEventCallback;

    s_ConsumerHandle = OpenTraceW(&logFile);
    if (s_ConsumerHandle == INVALID_PROCESSTRACE_HANDLE) {
        DWORD err = GetLastError();
        std::printf("SentinelAgent: OpenTraceW failed (error %lu)\n", err);
        return;
    }

    /*
     * ProcessTrace blocks until the session is stopped via ControlTrace.
     * Events are delivered to EtwEventCallback on this thread.
     */
    ULONG status = ProcessTrace(&s_ConsumerHandle, 1, NULL, NULL);

    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED && status != 1223) {
        std::printf("SentinelAgent: ProcessTrace failed (status=%lu)\n", status);
    }
}

/* ── Event callback ─────────────────────────────────────────────────────── */

/*
 * Called by ProcessTrace for each event. Dispatches to the appropriate
 * provider parser, then pushes the resulting SENTINEL_EVENT to the queue.
 *
 * IMPORTANT: This runs on the consumer thread (not a threadpool).
 * Keep processing fast — heavy work should be deferred to the
 * EventProcessor via the queue.
 */
static void WINAPI
EtwEventCallback(PEVENT_RECORD pEvent)
{
    if (!s_Initialized.load()) {
        return;
    }

    /* Skip our own process to avoid feedback loops */
    if (pEvent->EventHeader.ProcessId == GetCurrentProcessId()) {
        return;
    }

    SENTINEL_EVENT sEvent = {};
    bool parsed = false;

    /* Dispatch by provider GUID */
    if (IsEqualGUID(pEvent->EventHeader.ProviderId,
                    SENTINEL_ETW_DOTNET_RUNTIME)) {

        parsed = ParseDotNetEvent(pEvent, &sEvent);

    } else if (IsEqualGUID(pEvent->EventHeader.ProviderId,
                            SENTINEL_ETW_DNS_CLIENT)) {

        parsed = ParseDnsEvent(pEvent, &sEvent);

    } else if (IsEqualGUID(pEvent->EventHeader.ProviderId,
                            SENTINEL_ETW_POWERSHELL)) {

        parsed = ParsePowerShellEvent(pEvent, &sEvent);

    } else if (IsEqualGUID(pEvent->EventHeader.ProviderId,
                            SENTINEL_ETW_KERBEROS)) {

        parsed = ParseKerberosEvent(pEvent, &sEvent);
    }

    if (parsed) {
        /* Push directly to the pipeline event queue */
        g_EventQueue.Push(sEvent);
    }
}
