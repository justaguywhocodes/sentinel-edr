/*
 * sentinel-agent/pipeline.cpp
 * Event processing pipeline implementation.
 *
 * Four thread groups:
 *   1. Driver port receiver — connects to \SentinelPort, receives
 *      SENTINEL_FILTER_MSG via FilterGetMessage, pushes events to queue.
 *   2. Pipe server — listens on \\.\pipe\SentinelTelemetry, accepts
 *      hook DLL connections, spawns per-client handler threads that
 *      deserialize events and push to queue.
 *   3. ETW consumer thread — blocked on ProcessTrace, receives real-time
 *      ETW events and pushes them to the queue.
 *   4. Processing thread — dequeues events and logs them.
 */

#include <windows.h>
#include <fltUser.h>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <algorithm>
#include <atomic>
#include <chrono>

#include "pipeline.h"
#include "event_processor.h"
#include "etw/etw_consumer.h"
#include "amsi/amsi_register.h"
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

EventQueue                  g_EventQueue;
std::atomic<bool>           g_Shutdown{false};
static HANDLE               g_ShutdownEvent = nullptr;

/* Threads */
static std::thread          g_PortReceiverThread;
static std::thread          g_PipeListenerThread;
static std::thread          g_ProcessorThread;
static std::vector<std::thread> g_ClientThreads;
static std::mutex           g_ClientThreadsMutex;

/* Active client pipe handles — tracked so PipelineStop() can CancelIoEx */
static std::vector<HANDLE>  g_ClientPipes;
static std::mutex           g_ClientPipesMutex;

/* Event processor */
static EventProcessor       g_EventProcessor;

/* ── Helper: Log a status message to stdout ──────────────────────────────── */

static void
AgentLog(const char* fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    va_end(args);

    std::printf("%s", buf);
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

/* Global port handle so PipelineStop() can close it to unblock FilterGetMessage */
static HANDLE g_DriverPort = INVALID_HANDLE_VALUE;
static std::mutex g_DriverPortMutex;

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

        /* Publish handle so PipelineStop() can close it to unblock us */
        {
            std::lock_guard<std::mutex> lock(g_DriverPortMutex);
            g_DriverPort = hPort;
        }

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

        {
            std::lock_guard<std::mutex> lock(g_DriverPortMutex);
            if (g_DriverPort != INVALID_HANDLE_VALUE) {
                /* PipelineStop() hasn't closed it yet — we close it */
                g_DriverPort = INVALID_HANDLE_VALUE;
                CloseHandle(hPort);
            }
            /* else: PipelineStop() already closed it to unblock us */
        }
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

    /* Register handle so PipelineStop() can CancelIoEx to unblock ReadFile */
    {
        std::lock_guard<std::mutex> lock(g_ClientPipesMutex);
        g_ClientPipes.push_back(hPipe);
    }

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

    /* Unregister handle before closing */
    {
        std::lock_guard<std::mutex> lock(g_ClientPipesMutex);
        g_ClientPipes.erase(
            std::remove(g_ClientPipes.begin(), g_ClientPipes.end(), hPipe),
            g_ClientPipes.end());
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
    AgentLog("SentinelAgent: Processing thread started\n");

    auto lastTableDump = std::chrono::steady_clock::now();
    constexpr auto TABLE_DUMP_INTERVAL = std::chrono::seconds(30);

    while (!g_Shutdown.load()) {
        SENTINEL_EVENT event = {};

        if (!g_EventQueue.Pop(event, 1000)) {
            /* Timeout — check if it's time for a periodic connection table dump */
            auto now = std::chrono::steady_clock::now();
            if (now - lastTableDump >= TABLE_DUMP_INTERVAL) {
                g_EventProcessor.GetNetworkTable().PrintSummary();
                lastTableDump = now;
            }
            continue;
        }

        g_EventProcessor.Process(event);

        /* Periodic connection table dump (also check after processing events) */
        auto now = std::chrono::steady_clock::now();
        if (now - lastTableDump >= TABLE_DUMP_INTERVAL) {
            g_EventProcessor.GetNetworkTable().PrintSummary();
            lastTableDump = now;
        }
    }

    /*
     * Discard remaining queued events on shutdown.
     * Processing the full backlog (thousands of hook/minifilter events)
     * would block the shutdown for minutes.  All events up to this point
     * have already been written to the JSON log.
     */

    AgentLog("SentinelAgent: Processing thread stopped (%llu events)\n",
             g_EventProcessor.EventsProcessed());
}

/* ── Pipeline lifecycle ───────────────────────────────────────────────────── */

void
PipelineStart()
{
    g_Shutdown.store(false);
    g_ShutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    /* Initialize event processor (JSON log + process table) */
    if (!g_EventProcessor.Init("C:\\SentinelPOC\\agent_events.jsonl")) {
        AgentLog("SentinelAgent: WARNING: Failed to open JSON log file\n");
    }

    AgentLog("SentinelAgent: Pipeline starting...\n");

    /* Initialize and start ETW consumer (before other threads) */
    if (EtwConsumerInit()) {
        EtwConsumerStart();
    } else {
        AgentLog("SentinelAgent: WARNING: ETW consumer init failed "
                 "(ETW events will not be collected)\n");
    }

    /* Register custom AMSI provider (after ETW so we can observe results) */
    if (!AmsiProviderRegister(L"C:\\SentinelPOC\\sentinel-amsi.dll")) {
        AgentLog("SentinelAgent: WARNING: AMSI provider registration failed "
                 "(AMSI scanning will not be active)\n");
    }

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

    /* Unregister AMSI provider (before ETW stop so cleanup is clean) */
    AmsiProviderUnregister();

    /* Stop ETW consumer first (unblocks ProcessTrace, joins its thread) */
    EtwConsumerStop();

    /*
     * Cancel blocking ReadFile on active pipe client handler threads.
     * Each handler sits in synchronous ReadFile — CancelIoEx unblocks it.
     */
    {
        std::lock_guard<std::mutex> lock(g_ClientPipesMutex);
        for (HANDLE h : g_ClientPipes) {
            CancelIoEx(h, nullptr);
        }
    }

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

    /* Close driver port to unblock FilterGetMessage() */
    {
        std::lock_guard<std::mutex> lock(g_DriverPortMutex);
        if (g_DriverPort != INVALID_HANDLE_VALUE) {
            CloseHandle(g_DriverPort);
            g_DriverPort = INVALID_HANDLE_VALUE;
        }
    }

    /* Join threads */
    if (g_PortReceiverThread.joinable()) {
        g_PortReceiverThread.join();
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

    g_EventProcessor.Shutdown();

    AgentLog("SentinelAgent: Pipeline stopped\n");
}
