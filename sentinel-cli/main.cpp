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
 *   rules update   — git pull + validate + hot-reload (P9-T4)
 *   connections    — show network connection table
 *   processes      — list tracked processes with metadata
 *   hooks          — show hook DLL status per process
 *   config         — show active agent configuration
 *
 * Flags:
 *   --json         — output raw JSON instead of formatted text
 *   --help / -h    — show usage
 *
 * P9-T1: Core CLI Commands.
 * P9-T2: Inspection Commands.
 * P9-T3: Configuration command.
 * P9-T4: Rules update command.
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
        "  rules update     Git pull + validate + hot-reload rules\n"
        "  connections      Show network connection table\n"
        "  processes        List tracked processes with integrity level\n"
        "  hooks            Show hook DLL status per process\n"
        "  config           Show active agent configuration\n"
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

/* ── P9-T2: Inspection command printers ──────────────────────────────────── */

static void
PrintConnections(const std::string& json)
{
    std::string countStr = JsonGetValue(json, "count");
    int total = atoi(countStr.c_str());

    if (total == 0) {
        std::printf("No connections recorded.\n");
        return;
    }

    std::printf("Network Connection Table (%d entries)\n", total);
    std::printf("%-18s %-7s %-6s %-7s %s\n",
                "Remote", "Port", "Proto", "Hits", "PIDs");
    std::printf("%-18s %-7s %-6s %-7s %s\n",
                "------", "----", "-----", "----", "----");

    size_t pos = json.find("\"connections\":[");
    if (pos == std::string::npos) return;
    pos += 15;

    while (pos < json.size()) {
        size_t objStart = json.find('{', pos);
        if (objStart == std::string::npos) break;

        /* Find matching } — need to skip nested [] for pids array */
        int depth = 0;
        size_t objEnd = objStart;
        for (size_t i = objStart; i < json.size(); i++) {
            if (json[i] == '{' || json[i] == '[') depth++;
            else if (json[i] == '}' || json[i] == ']') {
                depth--;
                if (depth == 0) { objEnd = i; break; }
            }
        }
        if (objEnd == objStart) break;

        std::string entry = json.substr(objStart, objEnd - objStart + 1);

        /* Extract PID array as string */
        std::string pidsStr;
        size_t pidsPos = entry.find("\"pids\":[");
        if (pidsPos != std::string::npos) {
            size_t pidsStart = pidsPos + 8;
            size_t pidsEnd = entry.find(']', pidsStart);
            if (pidsEnd != std::string::npos) {
                pidsStr = entry.substr(pidsStart, pidsEnd - pidsStart);
            }
        }

        std::printf("%-18s %-7s %-6s %-7s %s\n",
                    JsonGetString(entry, "remote").c_str(),
                    JsonGetValue(entry, "port").c_str(),
                    JsonGetString(entry, "proto").c_str(),
                    JsonGetValue(entry, "hits").c_str(),
                    pidsStr.c_str());

        pos = objEnd + 1;
    }
}

static void
PrintProcesses(const std::string& json)
{
    std::string countStr = JsonGetValue(json, "count");
    int total = atoi(countStr.c_str());

    if (total == 0) {
        std::printf("No processes tracked.\n");
        return;
    }

    std::printf("Tracked Processes (%d entries)\n", total);
    std::printf("%-8s %-8s %-10s %-9s %-6s %s\n",
                "PID", "PPID", "Integrity", "Elevated", "Alive", "Image");
    std::printf("%-8s %-8s %-10s %-9s %-6s %s\n",
                "---", "----", "---------", "--------", "-----", "-----");

    size_t pos = json.find("\"processes\":[");
    if (pos == std::string::npos) return;
    pos += 13;

    while (pos < json.size()) {
        size_t objStart = json.find('{', pos);
        if (objStart == std::string::npos) break;
        size_t objEnd = json.find('}', objStart);
        if (objEnd == std::string::npos) break;

        std::string entry = json.substr(objStart, objEnd - objStart + 1);

        std::printf("%-8s %-8s %-10s %-9s %-6s %s\n",
                    JsonGetValue(entry, "pid").c_str(),
                    JsonGetValue(entry, "ppid").c_str(),
                    JsonGetString(entry, "integrity").c_str(),
                    JsonGetValue(entry, "elevated").c_str(),
                    JsonGetValue(entry, "alive").c_str(),
                    JsonGetString(entry, "image").c_str());

        pos = objEnd + 1;
    }
}

static void
PrintHooks(const std::string& json)
{
    std::string countStr = JsonGetValue(json, "count");
    int total = atoi(countStr.c_str());

    if (total == 0) {
        std::printf("No alive processes tracked.\n");
        return;
    }

    std::printf("Hook Status (%d alive processes)\n", total);
    std::printf("%-8s %-8s %s\n",
                "PID", "Hooked", "Image");
    std::printf("%-8s %-8s %s\n",
                "---", "------", "-----");

    size_t pos = json.find("\"processes\":[");
    if (pos == std::string::npos) return;
    pos += 13;

    while (pos < json.size()) {
        size_t objStart = json.find('{', pos);
        if (objStart == std::string::npos) break;
        size_t objEnd = json.find('}', objStart);
        if (objEnd == std::string::npos) break;

        std::string entry = json.substr(objStart, objEnd - objStart + 1);

        std::string hooked = JsonGetValue(entry, "hooked");
        std::printf("%-8s %-8s %s\n",
                    JsonGetValue(entry, "pid").c_str(),
                    hooked == "true" ? "YES" : "no",
                    JsonGetString(entry, "image").c_str());

        pos = objEnd + 1;
    }
}

/* ── P9-T4: Git helper and rules update ──────────────────────────────────── */

/*
 * Run a git command and capture stdout.
 * Returns the process exit code, or -1 on launch failure.
 */
static int
RunGit(const std::string& args, std::string& output)
{
    output.clear();

    /* Use cmd /c to leverage shell PATH resolution for git */
    std::string cmdLine = "cmd /c git " + args;

    /* Set up stdout capture via pipe */
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        output = "CreatePipe failed";
        return -1;
    }

    /* Don't let the read end be inherited */
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessA(
        nullptr,
        const_cast<char*>(cmdLine.c_str()),
        nullptr, nullptr,
        TRUE,                   /* inherit handles */
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi);

    /* Close write end in parent so ReadFile sees EOF when child exits */
    CloseHandle(hWritePipe);

    if (!ok) {
        DWORD err = GetLastError();
        output = "CreateProcess failed (error " + std::to_string(err) + ")";
        CloseHandle(hReadPipe);
        return -1;
    }

    /* Read stdout */
    char buf[4096];
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr)
           && bytesRead > 0) {
        buf[bytesRead] = '\0';
        output += buf;
    }

    CloseHandle(hReadPipe);

    WaitForSingleObject(pi.hProcess, 30000);

    DWORD exitCode = (DWORD)-1;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exitCode;
}

/*
 * Check if a directory contains a .git subdirectory.
 */
static bool
IsGitRepo(const std::string& dir)
{
    std::string gitDir = dir + "\\.git";
    DWORD attr = GetFileAttributesA(gitDir.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES
            && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

/*
 * Get the current HEAD SHA of a git repo.
 */
static std::string
GitGetHead(const std::string& dir)
{
    std::string output;
    std::string args = "-C \"" + dir + "\" rev-parse HEAD";
    int rc = RunGit(args, output);
    if (rc != 0) return "";

    /* Trim trailing whitespace */
    while (!output.empty() &&
           (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();
    return output;
}

/*
 * Run `rules update` command.
 * Returns 0 on success, 1 on failure.
 * Handles git pull, agent validation, and rollback.
 */
static int
DoRulesUpdate(bool jsonOutput)
{
    /* Default rule directories */
    const std::string rulesDir     = "C:\\SentinelPOC\\rules";
    const std::string yaraRulesDir = "C:\\SentinelPOC\\yara-rules";

    struct RepoInfo {
        std::string dir;
        std::string name;
        std::string savedHead;
    };

    RepoInfo repos[] = {
        { rulesDir,     "detection rules", "" },
        { yaraRulesDir, "YARA rules",      "" },
    };

    /* 1. Verify both directories are git repos */
    for (auto& repo : repos) {
        if (!IsGitRepo(repo.dir)) {
            std::fprintf(stderr,
                "Error: %s is not a git repository.\n"
                "Run 'sentinel-cli rules update --init "
                "--rules-repo <url> --yara-repo <url>' first.\n",
                repo.dir.c_str());
            return 1;
        }
    }

    /* 2. Save HEAD SHAs for rollback */
    for (auto& repo : repos) {
        repo.savedHead = GitGetHead(repo.dir);
        if (repo.savedHead.empty()) {
            std::fprintf(stderr,
                "Error: Cannot read HEAD for %s\n", repo.dir.c_str());
            return 1;
        }
    }

    /* 3. Git pull both repos */
    for (auto& repo : repos) {
        std::printf("Pulling %s (%s)...\n", repo.name.c_str(),
                    repo.dir.c_str());

        std::string output;
        std::string args = "-C \"" + repo.dir + "\" pull --ff-only";
        int rc = RunGit(args, output);

        if (rc != 0) {
            std::fprintf(stderr, "Error: git pull failed for %s:\n%s\n",
                        repo.dir.c_str(), output.c_str());
            /* Rollback already-pulled repos */
            for (auto& r : repos) {
                if (!r.savedHead.empty() && IsGitRepo(r.dir)) {
                    std::string resetArgs = "-C \"" + r.dir
                        + "\" reset --hard " + r.savedHead;
                    std::string dummy;
                    RunGit(resetArgs, dummy);
                }
            }
            return 1;
        }

        /* Trim and show output */
        while (!output.empty() &&
               (output.back() == '\n' || output.back() == '\r'))
            output.pop_back();
        std::printf("  %s\n", output.c_str());
    }

    /* 4. Send validate-and-reload command to agent */
    std::printf("Validating and reloading...\n");

    HANDLE hPipe = ConnectToAgent();
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr,
            "Error: Cannot connect to agent for validation.\n"
            "Rolling back...\n");
        for (auto& r : repos) {
            std::string args = "-C \"" + r.dir
                + "\" reset --hard " + r.savedHead;
            std::string dummy;
            RunGit(args, dummy);
        }
        return 1;
    }

    std::string json = SendCommand(hPipe, SentinelCmdRulesUpdate, nullptr);
    CloseHandle(hPipe);

    if (json.empty()) {
        std::fprintf(stderr, "Error: No response from agent.\n");
        return 1;
    }

    /* 5. Check validation result */
    std::string validated = JsonGetValue(json, "validated");

    if (validated != "true") {
        /* Validation failed — rollback */
        std::string error = JsonGetString(json, "error");
        std::fprintf(stderr, "Validation FAILED: %s\n", error.c_str());
        std::fprintf(stderr, "Rolling back git changes...\n");

        for (auto& r : repos) {
            std::string args = "-C \"" + r.dir
                + "\" reset --hard " + r.savedHead;
            std::string dummy;
            RunGit(args, dummy);
        }

        std::fprintf(stderr, "Rollback complete. Old rules remain active.\n");
        return 1;
    }

    /* 6. Success */
    if (jsonOutput) {
        std::printf("%s\n", json.c_str());
    } else {
        std::printf("Rules updated successfully.\n");
        std::printf("  Single-event: %s\n", JsonGetValue(json, "single").c_str());
        std::printf("  Sequence:     %s\n", JsonGetValue(json, "sequence").c_str());
        std::printf("  Threshold:    %s\n", JsonGetValue(json, "threshold").c_str());
        std::printf("  YARA:         %s\n", JsonGetValue(json, "yara").c_str());
    }

    return 0;
}

/*
 * Run `rules update --init` command.
 * Clones rule repos into the default directories.
 */
static int
DoRulesInit(int argc, char* argv[], bool jsonOutput)
{
    /* Parse --rules-repo and --yara-repo from remaining args */
    std::string rulesRepoUrl;
    std::string yaraRepoUrl;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--rules-repo") == 0 && i + 1 < argc) {
            rulesRepoUrl = argv[++i];
        } else if (strcmp(argv[i], "--yara-repo") == 0 && i + 1 < argc) {
            yaraRepoUrl = argv[++i];
        }
    }

    if (rulesRepoUrl.empty() || yaraRepoUrl.empty()) {
        std::fprintf(stderr,
            "Error: --init requires both repo URLs.\n"
            "Usage: sentinel-cli rules update --init "
            "--rules-repo <url> --yara-repo <url>\n");
        return 1;
    }

    const std::string rulesDir     = "C:\\SentinelPOC\\rules";
    const std::string yaraRulesDir = "C:\\SentinelPOC\\yara-rules";

    struct CloneInfo {
        std::string url;
        std::string dir;
        std::string name;
    };

    CloneInfo clones[] = {
        { rulesRepoUrl,  rulesDir,     "detection rules" },
        { yaraRepoUrl,   yaraRulesDir, "YARA rules"      },
    };

    for (auto& c : clones) {
        if (IsGitRepo(c.dir)) {
            std::printf("  %s: already initialized (%s)\n",
                        c.name.c_str(), c.dir.c_str());
            continue;
        }

        std::printf("Cloning %s from %s...\n", c.name.c_str(),
                    c.url.c_str());

        std::string output;
        std::string args = "clone \"" + c.url + "\" \"" + c.dir + "\"";
        int rc = RunGit(args, output);

        if (rc != 0) {
            std::fprintf(stderr, "Error: git clone failed:\n%s\n",
                        output.c_str());
            return 1;
        }
        std::printf("  Done.\n");
    }

    /* Send validate-and-reload to agent (if running) */
    HANDLE hPipe = ConnectToAgent();
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::printf("Agent not running. Rules will be loaded on next start.\n");
        return 0;
    }

    std::string json = SendCommand(hPipe, SentinelCmdRulesUpdate, nullptr);
    CloseHandle(hPipe);

    if (!json.empty()) {
        std::string validated = JsonGetValue(json, "validated");
        if (validated == "true") {
            if (jsonOutput) {
                std::printf("%s\n", json.c_str());
            } else {
                std::printf("Rules loaded:\n");
                std::printf("  Single-event: %s\n", JsonGetValue(json, "single").c_str());
                std::printf("  Sequence:     %s\n", JsonGetValue(json, "sequence").c_str());
                std::printf("  Threshold:    %s\n", JsonGetValue(json, "threshold").c_str());
                std::printf("  YARA:         %s\n", JsonGetValue(json, "yara").c_str());
            }
        } else {
            std::fprintf(stderr, "Warning: Rules validation failed: %s\n",
                        JsonGetString(json, "error").c_str());
        }
    }

    return 0;
}

/* ── P9-T3: Config printer ───────────────────────────────────────────────── */

static void
PrintConfig(const std::string& json)
{
    /* Extract nested values — "paths":{...}, "scanner":{...}, etc. */
    /* We reuse JsonGetString/JsonGetValue which work on the flat json string
       because our keys are unique across all sub-objects. */
    std::printf("SentinelPOC Agent Configuration\n");
    std::printf("================================\n");

    std::string configFile = JsonGetString(json, "config_file");
    if (configFile.empty()) {
        std::printf("  Config file:   (defaults — no file loaded)\n");
    } else {
        std::printf("  Config file:   %s\n", configFile.c_str());
    }

    std::printf("\n  [paths]\n");
    std::printf("  Log path:      %s\n",
                JsonGetString(json, "log_path").c_str());
    std::printf("  AMSI DLL:      %s\n",
                JsonGetString(json, "amsi_dll").c_str());
    std::printf("  Rules dir:     %s\n",
                JsonGetString(json, "rules_dir").c_str());
    std::printf("  YARA rules:    %s\n",
                JsonGetString(json, "yara_rules_dir").c_str());

    std::printf("\n  [scanner]\n");
    std::printf("  Max file size: %s MB\n",
                JsonGetValue(json, "max_file_size_mb").c_str());
    std::printf("  Max region:    %s MB\n",
                JsonGetValue(json, "max_region_size_mb").c_str());
    std::printf("  Cache TTL:     %s seconds\n",
                JsonGetValue(json, "cache_ttl_sec").c_str());

    std::printf("\n  [logging]\n");
    std::printf("  Max log size:  %s MB\n",
                JsonGetValue(json, "max_log_size_mb").c_str());

    std::printf("\n  [network]\n");
    std::printf("  Max events/s:  %s\n",
                JsonGetValue(json, "max_events_per_sec").c_str());

    std::string rulesRepo = JsonGetString(json, "rules_repo_url");
    std::string yaraRepo  = JsonGetString(json, "yara_rules_repo_url");
    if (!rulesRepo.empty() || !yaraRepo.empty()) {
        std::printf("\n  [git]\n");
        std::printf("  Rules repo:    %s\n",
                    rulesRepo.empty() ? "(not configured)" : rulesRepo.c_str());
        std::printf("  YARA repo:     %s\n",
                    yaraRepo.empty() ? "(not configured)" : yaraRepo.c_str());
    }

    std::printf("\n  [output.siem]\n");
    std::string siemEnabled  = JsonGetValue(json, "enabled");
    std::string siemEndpoint = JsonGetString(json, "endpoint");
    std::string siemApiKey   = JsonGetString(json, "api_key");
    std::printf("  Enabled:       %s\n",
                siemEnabled == "true" ? "yes" : "no");
    if (siemEnabled == "true") {
        std::printf("  Endpoint:      %s\n",
                    siemEndpoint.empty() ? "(not configured)" : siemEndpoint.c_str());
        std::printf("  API key:       %s\n",
                    siemApiKey.empty() ? "(not configured)" : siemApiKey.c_str());
        std::printf("  Batch size:    %s\n",
                    JsonGetValue(json, "batch_size").c_str());
        std::printf("  Flush interval:%s seconds\n",
                    JsonGetValue(json, "flush_interval_sec").c_str());
        std::printf("  Spill max:     %s MB\n",
                    JsonGetValue(json, "spill_max_size_mb").c_str());
    }
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
        if (argc < 3) {
            std::fprintf(stderr, "Error: expected 'rules reload' or 'rules update'\n");
            return 1;
        }
        if (strcmp(argv[2], "update") == 0) {
            /* P9-T4: rules update handled separately (git + IPC) */
            bool hasInit = false;
            for (int i = 3; i < argc; i++) {
                if (strcmp(argv[i], "--init") == 0) hasInit = true;
            }
            if (hasInit) {
                return DoRulesInit(argc, argv, jsonOutput);
            }
            return DoRulesUpdate(jsonOutput);
        }
        if (strcmp(argv[2], "reload") != 0) {
            std::fprintf(stderr, "Error: expected 'rules reload' or 'rules update'\n");
            return 1;
        }
        cmdType = SentinelCmdRulesReload;

    } else if (strcmp(command, "connections") == 0) {
        cmdType = SentinelCmdConnections;

    } else if (strcmp(command, "processes") == 0) {
        cmdType = SentinelCmdProcesses;

    } else if (strcmp(command, "hooks") == 0) {
        cmdType = SentinelCmdHooks;

    } else if (strcmp(command, "config") == 0) {
        cmdType = SentinelCmdConfig;

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
        case SentinelCmdConnections: PrintConnections(json);  break;
        case SentinelCmdProcesses:   PrintProcesses(json);    break;
        case SentinelCmdHooks:       PrintHooks(json);        break;
        case SentinelCmdConfig:      PrintConfig(json);       break;
        default: std::printf("%s\n", json.c_str()); break;
        }
    }

    return 0;
}
