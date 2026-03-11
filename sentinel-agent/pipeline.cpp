/*
 * sentinel-agent/pipeline.cpp
 * Event processing pipeline implementation.
 *
 * Three thread groups:
 *   1. Driver port receiver — connects to \SentinelPort, receives
 *      SENTINEL_FILTER_MSG via FilterGetMessage, pushes events to queue.
 *   2. Pipe server — listens on \\.\pipe\SentinelTelemetry, accepts
 *      hook DLL connections, spawns per-client handler threads that
 *      deserialize events and push to queue.
 *   3. Processing thread — dequeues events and logs them.
 */

#include <windows.h>
#include <fltUser.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>

#include "pipeline.h"
#include "ipc.h"
#include "ipc_serialize.h"
#include "constants.h"

/* ── EventQueue implementation ────────────────────────────────────────────── */

void
EventQueue::Push(const SENTINEL_EVENT& evt)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push_back(evt);
    }
    m_cv.notify_one();
}

bool
EventQueue::Pop(SENTINEL_EVENT& evt, DWORD timeoutMs)
{
    std::unique_lock<std::mutex> lock(m_mutex);

    if (!m_cv.wait_for(lock,
            std::chrono::milliseconds(timeoutMs),
            [this] { return !m_queue.empty() || m_shutdown; })) {
        return false;   /* Timeout */
    }

    if (m_shutdown && m_queue.empty()) {
        return false;
    }

    evt = m_queue.front();
    m_queue.pop_front();
    return true;
}

void
EventQueue::Shutdown()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
    }
    m_cv.notify_all();
}

size_t
EventQueue::Size()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.size();
}

/* ── Global pipeline state ────────────────────────────────────────────────── */

static EventQueue           g_EventQueue;
static std::atomic<bool>    g_Shutdown{false};
static HANDLE               g_ShutdownEvent = nullptr;

/* Threads */
static std::thread          g_PortReceiverThread;
static std::thread          g_PipeListenerThread;
static std::thread          g_ProcessorThread;
static std::vector<std::thread> g_ClientThreads;
static std::mutex           g_ClientThreadsMutex;

/* Event log file */
static HANDLE               g_hEventLog = INVALID_HANDLE_VALUE;

/* ── Helper: Log a message ────────────────────────────────────────────────── */

static void
AgentLog(const char* fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    va_end(args);

    /* Always print to stdout (console mode) */
    std::printf("%s", buf);

    /* Also write to log file if open */
    if (g_hEventLog != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_hEventLog, buf, (DWORD)strlen(buf), &written, nullptr);
    }
}

/* ── Helper: Hook function name ───────────────────────────────────────────── */

static const char* g_HookFuncNames[] = {
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtCreateThreadEx",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtQueueApcThread",
    "NtOpenProcess",
    "NtSuspendThread",
    "NtResumeThread",
    "NtCreateSection",
};

static const char*
HookFunctionName(int func)
{
    if (func >= 0 && func < (int)(sizeof(g_HookFuncNames) / sizeof(g_HookFuncNames[0]))) {
        return g_HookFuncNames[func];
    }
    return "Unknown";
}

/* ── Helper: Event source name ────────────────────────────────────────────── */

static const char* g_SourceNames[] = {
    "DriverProcess", "DriverThread", "DriverObject",
    "DriverImageLoad", "DriverRegistry", "DriverMinifilter",
    "DriverNetwork", "HookDll", "Etw", "Amsi",
    "Scanner", "RuleEngine", "SelfProtect",
};

static const char*
SourceName(int src)
{
    if (src >= 0 && src < (int)(sizeof(g_SourceNames) / sizeof(g_SourceNames[0]))) {
        return g_SourceNames[src];
    }
    return "Unknown";
}

/* ── Driver port receiver thread ──────────────────────────────────────────── */

/*
 * Message buffer for FilterGetMessage. The filter manager prepends
 * FILTER_MESSAGE_HEADER before the message body.
 */
typedef struct _AGENT_FILTER_MSG {
    FILTER_MESSAGE_HEADER   Header;
    SENTINEL_FILTER_MSG     Body;
} AGENT_FILTER_MSG;

static void
DriverPortReceiverThread()
{
    HANDLE  hPort = INVALID_HANDLE_VALUE;
    HRESULT hr;
    DWORD   backoffMs = 1000;

    AgentLog("SentinelAgent: Driver port receiver started\n");

    while (!g_Shutdown.load()) {
        /* Attempt to connect to the driver filter port */
        hr = FilterConnectCommunicationPort(
            SENTINEL_FILTER_PORT_NAME,
            0,          /* Options */
            nullptr,    /* Context */
            0,          /* Context size */
            nullptr,    /* Security attributes */
            &hPort);

        if (FAILED(hr)) {
            AgentLog("SentinelAgent: Driver port not available (0x%08lX), "
                     "retrying in %lums...\n", hr, backoffMs);
            WaitForSingleObject(g_ShutdownEvent, backoffMs);
            if (backoffMs < 5000) {
                backoffMs = min(backoffMs * 2, 5000UL);
            }
            continue;
        }

        AgentLog("SentinelAgent: Connected to driver port\n");
        backoffMs = 1000;

        /* Receive loop */
        while (!g_Shutdown.load()) {
            AGENT_FILTER_MSG    msg = {};
            DWORD               bytesReturned = 0;

            hr = FilterGetMessage(
                hPort,
                &msg.Header,
                sizeof(msg),
                nullptr);   /* No overlapped */

            if (FAILED(hr)) {
                if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                    break;  /* Shutdown */
                }
                AgentLog("SentinelAgent: FilterGetMessage failed 0x%08lX\n", hr);
                break;  /* Reconnect */
            }

            /* Push the event into the queue */
            g_EventQueue.Push(msg.Body.Event);
        }

        CloseHandle(hPort);
        hPort = INVALID_HANDLE_VALUE;
    }

    AgentLog("SentinelAgent: Driver port receiver stopped\n");
}

/* ── Pipe client handler thread ───────────────────────────────────────────── */

static void
PipeClientHandler(HANDLE hPipe, DWORD clientPid)
{
    BYTE    readBuf[sizeof(UINT32) + sizeof(SENTINEL_IPC_EVENT_MSG) + sizeof(SENTINEL_EVENT)];
    UINT32  sequenceNum = 0;

    AgentLog("SentinelAgent: Pipe client connected (PID %lu)\n", clientPid);

    /* Read and process events until disconnect */
    while (!g_Shutdown.load()) {
        DWORD   bytesRead = 0;

        if (!ReadFile(hPipe, readBuf, sizeof(readBuf), &bytesRead, nullptr)
            || bytesRead == 0) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                break;  /* Client disconnected */
            }
            if (g_Shutdown.load()) break;
            AgentLog("SentinelAgent: Pipe read error %lu\n", err);
            break;
        }

        /* Check for disconnect message */
        if (bytesRead >= sizeof(UINT32) + sizeof(SENTINEL_IPC_HEADER)) {
            const auto* hdr = reinterpret_cast<const SENTINEL_IPC_HEADER*>(
                readBuf + sizeof(UINT32));
            if (hdr->Type == SentinelMsgDisconnect) {
                AgentLog("SentinelAgent: Client PID %lu sent disconnect\n",
                         clientPid);
                break;
            }
        }

        /* Deserialize event */
        SENTINEL_EVENT  event = {};
        UINT32          consumed = 0;

        auto status = SentinelIpcDeserializeEvent(
            readBuf, bytesRead, &event, &consumed);

        if (status == SentinelSerializeOk) {
            g_EventQueue.Push(event);
        }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    AgentLog("SentinelAgent: Pipe client PID %lu disconnected\n", clientPid);
}

/* ── Pipe server listener thread ──────────────────────────────────────────── */

static void
PipeListenerThread()
{
    AgentLog("SentinelAgent: Pipe server started on %ls\n",
             SENTINEL_PIPE_TELEMETRY);

    while (!g_Shutdown.load()) {
        /* Create a new pipe instance */
        HANDLE hPipe = CreateNamedPipeW(
            SENTINEL_PIPE_TELEMETRY,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            SENTINEL_PIPE_MAX_INSTANCES,
            SENTINEL_PIPE_OUT_BUFFER,
            SENTINEL_PIPE_IN_BUFFER,
            0,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            AgentLog("SentinelAgent: CreateNamedPipe failed %lu\n",
                     GetLastError());
            WaitForSingleObject(g_ShutdownEvent, 1000);
            continue;
        }

        /* Wait for a client to connect */
        BOOL connected = ConnectNamedPipe(hPipe, nullptr)
                         || (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected || g_Shutdown.load()) {
            CloseHandle(hPipe);
            continue;
        }

        /* Read handshake from client */
        BYTE    handshakeBuf[256] = {};
        DWORD   bytesRead = 0;
        DWORD   clientPid = 0;

        if (ReadFile(hPipe, handshakeBuf, sizeof(handshakeBuf),
                     &bytesRead, nullptr) && bytesRead > 0) {

            /* Parse the framed handshake */
            if (bytesRead >= sizeof(UINT32) + sizeof(SENTINEL_IPC_HANDSHAKE)) {
                UINT32 frameLen = *reinterpret_cast<UINT32*>(handshakeBuf);
                if (frameLen >= sizeof(SENTINEL_IPC_HANDSHAKE)) {
                    auto* hs = reinterpret_cast<SENTINEL_IPC_HANDSHAKE*>(
                        handshakeBuf + sizeof(UINT32));

                    if (SentinelIpcHeaderValidate(&hs->Header) == SentinelSerializeOk
                        && hs->Header.Type == SentinelMsgHandshake) {
                        clientPid = hs->ClientPid;

                        /* Send handshake reply */
                        SENTINEL_IPC_HANDSHAKE_REPLY reply;
                        SentinelIpcBuildHandshakeReply(
                            &reply,
                            SentinelHandshakeOk,
                            GetCurrentProcessId(),
                            hs->Header.SequenceNum);

                        BYTE    replyBuf[128];
                        UINT32  replyBytes = 0;
                        if (SentinelIpcWriteFrame(replyBuf, sizeof(replyBuf),
                                &reply, sizeof(reply),
                                &replyBytes) == SentinelSerializeOk) {
                            DWORD written = 0;
                            WriteFile(hPipe, replyBuf, replyBytes,
                                      &written, nullptr);
                        }
                    }
                }
            }
        }

        if (clientPid == 0) {
            /* Bad handshake — reject */
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            AgentLog("SentinelAgent: Rejected pipe client (bad handshake)\n");
            continue;
        }

        /* Spawn a handler thread for this client */
        {
            std::lock_guard<std::mutex> lock(g_ClientThreadsMutex);
            g_ClientThreads.emplace_back(PipeClientHandler, hPipe, clientPid);
        }
    }

    AgentLog("SentinelAgent: Pipe server stopped\n");
}

/* ── Processing thread ────────────────────────────────────────────────────── */

static void
ProcessorThread()
{
    ULONGLONG eventsProcessed = 0;

    AgentLog("SentinelAgent: Processing thread started\n");

    while (!g_Shutdown.load()) {
        SENTINEL_EVENT event = {};

        if (!g_EventQueue.Pop(event, 1000)) {
            continue;   /* Timeout or shutdown */
        }

        eventsProcessed++;

        /* Format and log the event */
        if (event.Source == SentinelSourceHookDll) {
            const auto& hook = event.Payload.Hook;
            AgentLog("[%llu] source=%s func=%s pid=%lu targetPid=%lu "
                     "addr=0x%p size=0x%Ix prot=0x%lX status=0x%08lX\n",
                     eventsProcessed,
                     SourceName(event.Source),
                     HookFunctionName(hook.Function),
                     event.ProcessCtx.ProcessId,
                     hook.TargetProcessId,
                     (void*)(uintptr_t)hook.BaseAddress,
                     hook.RegionSize,
                     hook.Protection,
                     hook.ReturnStatus);
        } else {
            AgentLog("[%llu] source=%s pid=%lu\n",
                     eventsProcessed,
                     SourceName(event.Source),
                     event.ProcessCtx.ProcessId);
        }
    }

    /* Drain remaining events */
    {
        SENTINEL_EVENT event = {};
        while (g_EventQueue.Pop(event, 0)) {
            eventsProcessed++;
        }
    }

    AgentLog("SentinelAgent: Processing thread stopped (%llu events)\n",
             eventsProcessed);
}

/* ── Pipeline lifecycle ───────────────────────────────────────────────────── */

void
PipelineStart()
{
    g_Shutdown.store(false);
    g_ShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    /* Open event log file */
    g_hEventLog = CreateFileA(
        "C:\\SentinelPOC\\agent_events.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    AgentLog("SentinelAgent: Pipeline starting...\n");

    /* Start threads */
    g_PortReceiverThread = std::thread(DriverPortReceiverThread);
    g_PipeListenerThread = std::thread(PipeListenerThread);
    g_ProcessorThread    = std::thread(ProcessorThread);
}

void
PipelineStop()
{
    AgentLog("SentinelAgent: Pipeline stopping...\n");

    /* Signal shutdown */
    g_Shutdown.store(true);
    if (g_ShutdownEvent != nullptr) {
        SetEvent(g_ShutdownEvent);
    }
    g_EventQueue.Shutdown();

    /*
     * Cancel blocking I/O on the pipe listener thread.
     * ConnectNamedPipe blocks waiting for a client — we need to unblock it.
     * Creating a dummy connection to the pipe wakes it up.
     */
    {
        HANDLE hDummy = CreateFileW(
            SENTINEL_PIPE_TELEMETRY,
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDummy != INVALID_HANDLE_VALUE) {
            CloseHandle(hDummy);
        }
    }

    /* Join threads */
    if (g_PortReceiverThread.joinable()) {
        /* Cancel FilterGetMessage blocking call */
        if (g_PortReceiverThread.joinable()) {
            g_PortReceiverThread.join();
        }
    }

    if (g_PipeListenerThread.joinable()) {
        g_PipeListenerThread.join();
    }

    if (g_ProcessorThread.joinable()) {
        g_ProcessorThread.join();
    }

    /* Join client handler threads */
    {
        std::lock_guard<std::mutex> lock(g_ClientThreadsMutex);
        for (auto& t : g_ClientThreads) {
            if (t.joinable()) {
                t.join();
            }
        }
        g_ClientThreads.clear();
    }

    /* Clean up */
    if (g_ShutdownEvent != nullptr) {
        CloseHandle(g_ShutdownEvent);
        g_ShutdownEvent = nullptr;
    }

    if (g_hEventLog != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hEventLog);
        g_hEventLog = INVALID_HANDLE_VALUE;
    }

    AgentLog("SentinelAgent: Pipeline stopped\n");
}
