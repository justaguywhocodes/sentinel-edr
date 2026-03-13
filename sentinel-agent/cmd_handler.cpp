/*
 * sentinel-agent/cmd_handler.cpp
 * Command pipe server implementation.
 *
 * Listens on \\.\pipe\SentinelCommand for CLI client connections,
 * dispatches commands, and returns JSON-encoded replies.
 *
 * P9-T1: Core CLI Commands.
 * Book reference: Chapter 1 — Agent Design.
 */

#include "cmd_handler.h"
#include "event_processor.h"
#include "pipeline.h"        /* g_EventQueue for queue depth */
#include "json_writer.h"     /* SeverityName(), SourceName() */
#include "ipc.h"
#include "ipc_serialize.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <deque>

/* ── Start / Stop ────────────────────────────────────────────────────────── */

void
CommandHandler::Start(EventProcessor* processor,
                      std::function<bool()> driverStatusFn)
{
    m_processor      = processor;
    m_driverStatusFn = std::move(driverStatusFn);
    m_startTime      = GetTickCount64();
    m_running.store(true);
    m_shutdownEvent  = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_thread         = std::thread(&CommandHandler::ServerThread, this);
}

void
CommandHandler::Stop()
{
    m_running.store(false);
    if (m_shutdownEvent) {
        SetEvent(m_shutdownEvent);
    }

    /* Cancel any blocking ConnectNamedPipe / ReadFile */
    if (m_activePipe != INVALID_HANDLE_VALUE) {
        CancelIoEx(m_activePipe, nullptr);
    }

    /* Wake the listener by connecting and immediately closing */
    HANDLE hDummy = CreateFileW(
        SENTINEL_PIPE_COMMAND,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDummy != INVALID_HANDLE_VALUE) {
        CloseHandle(hDummy);
    }

    if (m_thread.joinable()) {
        m_thread.join();
    }

    if (m_shutdownEvent) {
        CloseHandle(m_shutdownEvent);
        m_shutdownEvent = nullptr;
    }
}

/* ── Server thread ───────────────────────────────────────────────────────── */

void
CommandHandler::ServerThread()
{
    std::printf("SentinelAgent: Command server started on %ls\n",
                SENTINEL_PIPE_COMMAND);

    while (m_running.load()) {

        /* Create a new pipe instance (single instance — one CLI at a time) */
        HANDLE hPipe = CreateNamedPipeW(
            SENTINEL_PIPE_COMMAND,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,  /* max instances: 1 CLI at a time */
            SENTINEL_PIPE_OUT_BUFFER,
            SENTINEL_PIPE_IN_BUFFER,
            5000,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::printf("SentinelAgent: Command pipe create failed %lu\n",
                        GetLastError());
            WaitForSingleObject(m_shutdownEvent, 1000);
            continue;
        }

        m_activePipe = hPipe;

        /* Wait for a CLI client to connect */
        BOOL connected = ConnectNamedPipe(hPipe, nullptr)
                         || (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected || !m_running.load()) {
            CloseHandle(hPipe);
            m_activePipe = INVALID_HANDLE_VALUE;
            continue;
        }

        HandleClient(hPipe);

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        m_activePipe = INVALID_HANDLE_VALUE;
    }

    std::printf("SentinelAgent: Command server stopped\n");
}

/* ── Handle a single CLI client ──────────────────────────────────────────── */

void
CommandHandler::HandleClient(HANDLE hPipe)
{
    BYTE    readBuf[sizeof(UINT32) + sizeof(SENTINEL_IPC_COMMAND) + 256];
    DWORD   bytesRead = 0;

    /* 1. Read and validate handshake */
    if (!ReadFile(hPipe, readBuf, sizeof(readBuf), &bytesRead, nullptr)
        || bytesRead == 0) {
        return;
    }

    if (bytesRead >= sizeof(UINT32) + sizeof(SENTINEL_IPC_HANDSHAKE)) {
        auto* hs = reinterpret_cast<SENTINEL_IPC_HANDSHAKE*>(
            readBuf + sizeof(UINT32));

        if (SentinelIpcHeaderValidate(&hs->Header) != SentinelSerializeOk
            || hs->Header.Type != SentinelMsgHandshake
            || hs->ClientType != SentinelClientCli) {
            return;     /* Bad handshake */
        }

        /* Send handshake reply */
        SENTINEL_IPC_HANDSHAKE_REPLY reply;
        SentinelIpcBuildHandshakeReply(
            &reply, SentinelHandshakeOk,
            GetCurrentProcessId(),
            hs->Header.SequenceNum);

        BYTE    replyBuf[128];
        UINT32  replyBytes = 0;
        if (SentinelIpcWriteFrame(replyBuf, sizeof(replyBuf),
                &reply, sizeof(reply), &replyBytes) == SentinelSerializeOk) {
            DWORD written = 0;
            WriteFile(hPipe, replyBuf, replyBytes, &written, nullptr);
        }
    } else {
        return;     /* Incomplete handshake */
    }

    /* 2. Read command */
    bytesRead = 0;
    if (!ReadFile(hPipe, readBuf, sizeof(readBuf), &bytesRead, nullptr)
        || bytesRead == 0) {
        return;
    }

    if (bytesRead < sizeof(UINT32) + sizeof(SENTINEL_IPC_HEADER)) {
        return;
    }

    auto* cmd = reinterpret_cast<SENTINEL_IPC_COMMAND*>(
        readBuf + sizeof(UINT32));

    if (SentinelIpcHeaderValidate(&cmd->Header) != SentinelSerializeOk
        || cmd->Header.Type != SentinelMsgCommand) {
        return;
    }

    /* 3. Dispatch command and build JSON response */
    std::string json;
    UINT32 status = 0;

    switch (cmd->CommandType) {
    case SentinelCmdStatus:
        json = HandleStatus();
        break;
    case SentinelCmdAlerts:
        json = HandleAlerts(cmd->Argument);
        break;
    case SentinelCmdScan:
        json = HandleScan(cmd->Argument);
        break;
    case SentinelCmdRulesReload:
        json = HandleRulesReload();
        break;
    default:
        json = "{\"error\":\"Unknown command\"}";
        status = 1;
        break;
    }

    /* 4. Send reply */
    SendReply(hPipe, cmd->CommandType, status, json,
              cmd->Header.SequenceNum + 1);
}

/* ── Command handlers ────────────────────────────────────────────────────── */

std::string
CommandHandler::HandleStatus()
{
    ULONGLONG uptimeMs = GetTickCount64() - m_startTime;
    ULONGLONG uptimeS  = uptimeMs / 1000;

    auto counts = m_processor->GetRuleCounts();
    bool driverOk = m_driverStatusFn ? m_driverStatusFn() : false;

    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"agent\":\"running\","
        "\"uptime_s\":%llu,"
        "\"events\":%llu,"
        "\"driver\":%s,"
        "\"yara\":%s,"
        "\"yara_rules\":%d,"
        "\"rules\":{\"single\":%zu,\"sequence\":%zu,\"threshold\":%zu},"
        "\"queue_depth\":%zu}",
        uptimeS,
        m_processor->EventsProcessed(),
        driverOk ? "true" : "false",
        m_processor->IsYaraReady() ? "true" : "false",
        counts.yara,
        counts.singleEvent,
        counts.sequence,
        counts.threshold,
        g_EventQueue.Size());

    return buf;
}

std::string
CommandHandler::HandleAlerts(const wchar_t* arg)
{
    /* Parse optional count from argument (default 20) */
    int maxAlerts = 20;
    if (arg && arg[0] != L'\0') {
        int n = _wtoi(arg);
        if (n > 0 && n <= 100) maxAlerts = n;
    }

    auto history = m_processor->GetAlertHistory();

    std::string json = "{\"count\":";
    json += std::to_string(history.size());
    json += ",\"alerts\":[";

    /* Return the most recent maxAlerts entries */
    int start = (int)history.size() - maxAlerts;
    if (start < 0) start = 0;

    bool first = true;
    for (int i = start; i < (int)history.size(); i++) {
        const auto& alert = history[i];
        if (!first) json += ",";
        first = false;

        char entry[512];
        _snprintf_s(entry, sizeof(entry), _TRUNCATE,
            "{\"severity\":\"%s\","
            "\"rule\":\"%s\","
            "\"trigger\":\"%s\","
            "\"pid\":%lu}",
            SeverityName(alert.Severity),
            alert.Payload.Alert.RuleName,
            SourceName(alert.Payload.Alert.TriggerSource),
            alert.ProcessCtx.ProcessId);

        json += entry;
    }

    json += "]}";
    return json;
}

std::string
CommandHandler::HandleScan(const wchar_t* arg)
{
    if (!arg || arg[0] == L'\0') {
        return "{\"error\":\"No path specified\"}";
    }

    if (!m_processor->IsYaraReady()) {
        return "{\"error\":\"YARA scanner not ready\"}";
    }

    SENTINEL_SCANNER_EVENT result = {};
    bool ok = m_processor->ScanFileOnDemand(arg, result);

    if (!ok) {
        return "{\"error\":\"Scan failed (file not found or access denied)\"}";
    }

    /* Convert wide path to narrow for JSON */
    char narrowPath[SENTINEL_MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, arg, -1,
                        narrowPath, sizeof(narrowPath), nullptr, nullptr);

    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"path\":\"%s\","
        "\"match\":%s,"
        "\"rule\":\"%s\"}",
        narrowPath,
        result.IsMatch ? "true" : "false",
        result.IsMatch ? result.YaraRule : "(none)");

    /* Escape backslashes in path for valid JSON */
    std::string json = buf;
    size_t pos = 0;
    while ((pos = json.find('\\', pos)) != std::string::npos) {
        /* Only escape if not already escaped */
        if (pos + 1 < json.size() && json[pos + 1] == '\\') {
            pos += 2;
        } else if (pos + 1 < json.size() && json[pos + 1] == '"') {
            pos += 2;   /* Skip \" */
        } else {
            json.insert(pos, 1, '\\');
            pos += 2;
        }
    }

    return json;
}

std::string
CommandHandler::HandleRulesReload()
{
    bool ok = m_processor->ReloadRules();
    auto counts = m_processor->GetRuleCounts();

    char buf[256];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"reloaded\":%s,"
        "\"rules\":{\"single\":%zu,\"sequence\":%zu,\"threshold\":%zu}}",
        ok ? "true" : "false",
        counts.singleEvent,
        counts.sequence,
        counts.threshold);

    return buf;
}

/* ── Reply helper ────────────────────────────────────────────────────────── */

bool
CommandHandler::SendReply(HANDLE hPipe, UINT32 cmdType, UINT32 status,
                          const std::string& json, UINT32 seqNum)
{
    /*
     * Wire layout:
     *   [UINT32 frame_length]
     *   [SENTINEL_IPC_COMMAND_REPLY header]
     *   [JSON payload bytes]
     */
    SENTINEL_IPC_COMMAND_REPLY replyHdr = {};
    UINT32 jsonSize = (UINT32)json.size();
    UINT32 payloadAfterHeader = sizeof(replyHdr) - sizeof(SENTINEL_IPC_HEADER)
                              + jsonSize;

    SentinelIpcHeaderInit(&replyHdr.Header, SentinelMsgCommandReply,
                          payloadAfterHeader, seqNum);
    replyHdr.CommandType = cmdType;
    replyHdr.Status      = status;
    replyHdr.DataSize    = jsonSize;

    /* Assemble into a single buffer */
    UINT32 totalMsg = sizeof(replyHdr) + jsonSize;
    UINT32 totalFrame = sizeof(UINT32) + totalMsg;

    std::vector<BYTE> buf(totalFrame);

    /* Length prefix */
    *(UINT32*)buf.data() = totalMsg;

    /* Reply header */
    memcpy(buf.data() + sizeof(UINT32), &replyHdr, sizeof(replyHdr));

    /* JSON payload */
    if (jsonSize > 0) {
        memcpy(buf.data() + sizeof(UINT32) + sizeof(replyHdr),
               json.data(), jsonSize);
    }

    DWORD written = 0;
    return WriteFile(hPipe, buf.data(), totalFrame, &written, nullptr) != 0;
}
