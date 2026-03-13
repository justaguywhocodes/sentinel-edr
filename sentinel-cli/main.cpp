/*
 * sentinel-cli/main.cpp
 * Console management tool for SentinelPOC.
 *
 * Communicates with the running sentinel-agent over
 * \\.\pipe\SentinelCommand using the IPC protocol defined in ipc.h.
 *
 * Subcommands:
 *   status         — agent health, driver status, sensor states
 *   alerts [N]     — show last N alerts (default 20)
 *   scan <path>    — trigger on-demand YARA scan
 *   rules reload   — hot-reload detection rules
 *
 * Flags:
 *   --json         — output raw JSON instead of formatted text
 *   --help / -h    — show usage
 *
 * P9-T1: Core CLI Commands.
 * Book reference: Chapter 1 — Agent Design, SOC Workflow.
 */

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#include "ipc.h"
#include "ipc_serialize.h"

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static void
PrintUsage()
{
    std::printf(
        "SentinelPOC CLI v1.0.0\n"
        "\n"
        "Usage: sentinel-cli <command> [args] [--json]\n"
        "\n"
        "Commands:\n"
        "  status           Show agent health, driver status, rule counts\n"
        "  alerts [N]       Show last N alerts (default: 20)\n"
        "  scan <path>      Trigger on-demand YARA scan on a file\n"
        "  rules reload     Hot-reload detection rules from disk\n"
        "\n"
        "Flags:\n"
        "  --json           Output raw JSON\n"
        "  --help, -h       Show this help\n"
    );
}

/*
 * Connect to the agent command pipe and perform handshake.
 * Returns pipe handle on success, INVALID_HANDLE_VALUE on failure.
 */
static HANDLE
ConnectToAgent()
{
    HANDLE hPipe = CreateFileW(
        SENTINEL_PIPE_COMMAND,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PIPE_BUSY) {
            std::fprintf(stderr,
                "Error: Agent not running (pipe not found).\n"
                "Start sentinel-agent first.\n");
        } else {
            std::fprintf(stderr,
                "Error: Cannot connect to agent (error %lu)\n", err);
        }
        return INVALID_HANDLE_VALUE;
    }

    /* Send handshake */
    SENTINEL_IPC_HANDSHAKE hs;
    SentinelIpcBuildHandshake(&hs, SentinelClientCli,
                              GetCurrentProcessId(), 1);

    BYTE    hsBuf[128];
    UINT32  hsBytes = 0;
    if (SentinelIpcWriteFrame(hsBuf, sizeof(hsBuf),
            &hs, sizeof(hs), &hsBytes) != SentinelSerializeOk) {
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }

    DWORD written = 0;
    if (!WriteFile(hPipe, hsBuf, hsBytes, &written, nullptr)) {
        std::fprintf(stderr, "Error: Handshake send failed\n");
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }

    /* Read handshake reply */
    BYTE    replyBuf[128];
    DWORD   bytesRead = 0;
    if (!ReadFile(hPipe, replyBuf, sizeof(replyBuf), &bytesRead, nullptr)
        || bytesRead == 0) {
        std::fprintf(stderr, "Error: No handshake reply from agent\n");
        CloseHandle(hPipe);
        return INVALID_HANDLE_VALUE;
    }

    if (bytesRead >= sizeof(UINT32) + sizeof(SENTINEL_IPC_HANDSHAKE_REPLY)) {
        auto* reply = reinterpret_cast<SENTINEL_IPC_HANDSHAKE_REPLY*>(
            replyBuf + sizeof(UINT32));
        if (reply->Status != SentinelHandshakeOk) {
            std::fprintf(stderr, "Error: Agent rejected connection\n");
            CloseHandle(hPipe);
            return INVALID_HANDLE_VALUE;
        }
    }

    return hPipe;
}

/*
 * Send a command and read the JSON reply.
 * Returns empty string on failure.
 */
static std::string
SendCommand(HANDLE hPipe, SENTINEL_CMD_TYPE cmdType, const wchar_t* arg)
{
    /* Build command message */
    SENTINEL_IPC_COMMAND cmd = {};
    UINT32 payloadAfterHdr = sizeof(cmd) - sizeof(SENTINEL_IPC_HEADER);
    SentinelIpcHeaderInit(&cmd.Header, SentinelMsgCommand,
                          payloadAfterHdr, 2);
    cmd.CommandType = (UINT32)cmdType;

    if (arg && arg[0] != L'\0') {
        wcsncpy_s(cmd.Argument, SENTINEL_CMD_MAX_ARG, arg, _TRUNCATE);
    }

    /* Frame and send */
    BYTE    sendBuf[sizeof(UINT32) + sizeof(cmd)];
    UINT32  sendBytes = 0;
    if (SentinelIpcWriteFrame(sendBuf, sizeof(sendBuf),
            &cmd, sizeof(cmd), &sendBytes) != SentinelSerializeOk) {
        return "";
    }

    DWORD written = 0;
    if (!WriteFile(hPipe, sendBuf, sendBytes, &written, nullptr)) {
        std::fprintf(stderr, "Error: Failed to send command\n");
        return "";
    }

    /* Read reply: [UINT32 frame_len] [SENTINEL_IPC_COMMAND_REPLY] [JSON] */
    BYTE    recvBuf[SENTINEL_CMD_MAX_REPLY + 256];
    DWORD   bytesRead = 0;
    if (!ReadFile(hPipe, recvBuf, sizeof(recvBuf), &bytesRead, nullptr)
        || bytesRead == 0) {
        std::fprintf(stderr, "Error: No reply from agent\n");
        return "";
    }

    if (bytesRead < sizeof(UINT32) + sizeof(SENTINEL_IPC_COMMAND_REPLY)) {
        std::fprintf(stderr, "Error: Reply too short\n");
        return "";
    }

    auto* replyHdr = reinterpret_cast<SENTINEL_IPC_COMMAND_REPLY*>(
        recvBuf + sizeof(UINT32));

    if (SentinelIpcHeaderValidate(&replyHdr->Header) != SentinelSerializeOk) {
        std::fprintf(stderr, "Error: Invalid reply header\n");
        return "";
    }

    /* Extract JSON payload */
    UINT32 jsonSize = replyHdr->DataSize;
    const char* jsonData = reinterpret_cast<const char*>(
        recvBuf + sizeof(UINT32) + sizeof(SENTINEL_IPC_COMMAND_REPLY));

    if (jsonSize > 0 && sizeof(UINT32) + sizeof(SENTINEL_IPC_COMMAND_REPLY) + jsonSize <= bytesRead) {
        return std::string(jsonData, jsonSize);
    }

    return "{}";
}

/* ── Simple JSON value extraction (no external deps) ─────────────────────── */

/*
 * Extract a string value for a given key from a flat JSON object.
 * Very basic — handles simple cases only. No nesting.
 */
static std::string
JsonGetString(const std::string& json, const char* key)
{
    std::string searchKey = std::string("\"") + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    size_t end = json.find('"', pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

static std::string
JsonGetValue(const std::string& json, const char* key)
{
    std::string searchKey = std::string("\"") + key + "\":";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    pos += searchKey.size();
    /* Value ends at comma, closing brace, or bracket */
    size_t end = json.find_first_of(",}]", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

/* ── Pretty-print formatters ─────────────────────────────────────────────── */

static void
PrintStatus(const std::string& json)
{
    std::printf("SentinelPOC Agent Status\n");
    std::printf("========================\n");
    std::printf("  Agent:       %s\n", JsonGetString(json, "agent").c_str());
    std::printf("  Uptime:      %s seconds\n", JsonGetValue(json, "uptime_s").c_str());
    std::printf("  Events:      %s\n", JsonGetValue(json, "events").c_str());
    std::printf("  Driver:      %s\n", JsonGetValue(json, "driver").c_str());
    std::printf("  YARA:        %s (%s rules)\n",
                JsonGetValue(json, "yara").c_str(),
                JsonGetValue(json, "yara_rules").c_str());
    std::printf("  Queue depth: %s\n", JsonGetValue(json, "queue_depth").c_str());
    std::printf("  Rules:\n");
    std::printf("    Single-event: %s\n", JsonGetValue(json, "single").c_str());
    std::printf("    Sequence:     %s\n", JsonGetValue(json, "sequence").c_str());
    std::printf("    Threshold:    %s\n", JsonGetValue(json, "threshold").c_str());
}

static void
PrintAlerts(const std::string& json)
{
    std::string countStr = JsonGetValue(json, "count");
    int total = atoi(countStr.c_str());

    if (total == 0) {
        std::printf("No alerts recorded.\n");
        return;
    }

    std::printf("Recent Alerts (%d total in history)\n", total);
    std::printf("%-10s %-35s %-15s %s\n",
                "Severity", "Rule", "Trigger", "PID");
    std::printf("%-10s %-35s %-15s %s\n",
                "--------", "----", "-------", "---");

    /* Parse the alerts array — simple extraction */
    size_t pos = json.find("\"alerts\":[");
    if (pos == std::string::npos) return;
    pos += 10;  /* skip "alerts":[ */

    while (pos < json.size()) {
        size_t objStart = json.find('{', pos);
        if (objStart == std::string::npos) break;
        size_t objEnd = json.find('}', objStart);
        if (objEnd == std::string::npos) break;

        std::string entry = json.substr(objStart, objEnd - objStart + 1);

        std::printf("%-10s %-35s %-15s %s\n",
                    JsonGetString(entry, "severity").c_str(),
                    JsonGetString(entry, "rule").c_str(),
                    JsonGetString(entry, "trigger").c_str(),
                    JsonGetValue(entry, "pid").c_str());

        pos = objEnd + 1;
    }
}

static void
PrintScanResult(const std::string& json)
{
    std::string path  = JsonGetString(json, "path");
    std::string match = JsonGetValue(json, "match");
    std::string rule  = JsonGetString(json, "rule");
    std::string error = JsonGetString(json, "error");

    if (!error.empty()) {
        std::fprintf(stderr, "Error: %s\n", error.c_str());
        return;
    }

    std::printf("Scan Result\n");
    std::printf("  Path:  %s\n", path.c_str());
    std::printf("  Match: %s\n", match.c_str());
    if (match == "true") {
        std::printf("  Rule:  %s\n", rule.c_str());
    }
}

static void
PrintRulesReload(const std::string& json)
{
    std::string reloaded = JsonGetValue(json, "reloaded");
    if (reloaded == "true") {
        std::printf("Rules reloaded successfully.\n");
    } else {
        std::printf("Rules reload failed.\n");
    }
    std::printf("  Single-event: %s\n", JsonGetValue(json, "single").c_str());
    std::printf("  Sequence:     %s\n", JsonGetValue(json, "sequence").c_str());
    std::printf("  Threshold:    %s\n", JsonGetValue(json, "threshold").c_str());
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    /* Check for --help */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage();
            return 0;
        }
    }

    /* Check for --json flag */
    bool jsonOutput = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            jsonOutput = true;
        }
    }

    /* Parse command */
    const char* command = argv[1];
    SENTINEL_CMD_TYPE cmdType;
    wchar_t argument[SENTINEL_CMD_MAX_ARG] = {};

    if (strcmp(command, "status") == 0) {
        cmdType = SentinelCmdStatus;

    } else if (strcmp(command, "alerts") == 0) {
        cmdType = SentinelCmdAlerts;
        /* Optional count argument */
        if (argc >= 3 && argv[2][0] != '-') {
            MultiByteToWideChar(CP_UTF8, 0, argv[2], -1,
                                argument, SENTINEL_CMD_MAX_ARG);
        }

    } else if (strcmp(command, "scan") == 0) {
        cmdType = SentinelCmdScan;
        if (argc < 3 || argv[2][0] == '-') {
            std::fprintf(stderr, "Error: scan requires a file path\n");
            std::fprintf(stderr, "Usage: sentinel-cli scan <path>\n");
            return 1;
        }
        MultiByteToWideChar(CP_UTF8, 0, argv[2], -1,
                            argument, SENTINEL_CMD_MAX_ARG);

    } else if (strcmp(command, "rules") == 0) {
        if (argc < 3 || strcmp(argv[2], "reload") != 0) {
            std::fprintf(stderr, "Error: expected 'rules reload'\n");
            std::fprintf(stderr, "Usage: sentinel-cli rules reload\n");
            return 1;
        }
        cmdType = SentinelCmdRulesReload;

    } else {
        std::fprintf(stderr, "Error: Unknown command '%s'\n\n", command);
        PrintUsage();
        return 1;
    }

    /* Connect to agent */
    HANDLE hPipe = ConnectToAgent();
    if (hPipe == INVALID_HANDLE_VALUE) {
        return 1;
    }

    /* Send command and get reply */
    std::string json = SendCommand(hPipe, cmdType, argument);
    CloseHandle(hPipe);

    if (json.empty()) {
        return 1;
    }

    /* Output */
    if (jsonOutput) {
        std::printf("%s\n", json.c_str());
    } else {
        switch (cmdType) {
        case SentinelCmdStatus:       PrintStatus(json);       break;
        case SentinelCmdAlerts:       PrintAlerts(json);       break;
        case SentinelCmdScan:         PrintScanResult(json);   break;
        case SentinelCmdRulesReload:  PrintRulesReload(json);  break;
        default: std::printf("%s\n", json.c_str()); break;
        }
    }

    return 0;
}
