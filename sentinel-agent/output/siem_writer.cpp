/*
 * sentinel-agent/output/siem_writer.cpp
 * SIEM output writer implementation.
 *
 * P9-T5: SIEM Integration.
 */

#include "siem_writer.h"
#include "siem_serializer.h"
#include "../config.h"
#include "../json_writer.h"

#include <cstdio>
#include <cstring>
#include <chrono>
#include <fstream>

#pragma comment(lib, "winhttp.lib")

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static std::string
GetMachineHostname()
{
    char buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD len = sizeof(buf);
    if (GetComputerNameA(buf, &len)) {
        return std::string(buf, len);
    }
    return "unknown";
}

static std::string
GenerateAgentId()
{
    GUID guid;
    if (SUCCEEDED(CoCreateGuid(&guid))) {
        return JsonWriter::GuidToString(guid);
    }
    return "00000000-0000-0000-0000-000000000000";
}

/* ── SiemWriter lifecycle ────────────────────────────────────────────────── */

SiemWriter::SiemWriter()
    : m_enabled(false)
    , m_batchSize(100)
    , m_flushIntervalSec(10)
    , m_spillMaxBytes(500ULL * 1024 * 1024)
    , m_port(443)
    , m_useHttps(true)
    , m_shutdown(false)
    , m_hSession(nullptr)
{}

SiemWriter::~SiemWriter()
{
    Shutdown();
}

bool
SiemWriter::Init(const SentinelConfig& cfg)
{
    m_enabled = cfg.siemEnabled;

    if (!m_enabled) {
        return true;    /* Disabled — no-op, not an error */
    }

    /* Config */
    m_endpoint         = cfg.siemEndpoint;
    m_apiKey           = cfg.siemApiKey;
    m_batchSize        = cfg.siemBatchSize > 0 ? cfg.siemBatchSize : 100;
    m_flushIntervalSec = cfg.siemFlushIntervalSec > 0
                             ? cfg.siemFlushIntervalSec : 10;
    m_spillMaxBytes    = (UINT64)cfg.siemSpillMaxSizeMb * 1024 * 1024;

    /* Spill file path: next to the log file.
     * Derive the directory from logPath so the spill file lands in the
     * same folder as agent_events.jsonl. */
    m_spillPath = cfg.logPath;
    m_spillPath += ".siem-spill";

    /* Ensure the parent directory exists (handles the case where logPath's
     * directory hasn't been created yet). */
    {
        std::string dir = m_spillPath;
        auto pos = dir.find_last_of("\\/");
        if (pos != std::string::npos) {
            dir.resize(pos);
            CreateDirectoryA(dir.c_str(), nullptr);  /* OK if it already exists */
        }
    }

    /* Identity */
    m_hostname = GetMachineHostname();
    m_agentId  = GenerateAgentId();

    /* Parse endpoint URL */
    if (!ParseEndpointUrl()) {
        std::printf("SentinelAgent: SIEM writer: invalid endpoint URL: %s\n",
                    m_endpoint.c_str());
        m_enabled = false;
        return false;
    }

    /* Open WinHTTP session */
    m_hSession = WinHttpOpen(
        L"SentinelEDR/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!m_hSession) {
        std::printf("SentinelAgent: SIEM writer: WinHttpOpen failed (%lu)\n",
                    GetLastError());
        m_enabled = false;
        return false;
    }

    /* Start worker thread */
    m_shutdown = false;
    m_workerThread = std::thread(&SiemWriter::WorkerLoop, this);

    std::printf("SentinelAgent: SIEM writer started → %s "
                "(batch=%u, flush=%us)\n",
                m_endpoint.c_str(), m_batchSize, m_flushIntervalSec);

    return true;
}

void
SiemWriter::Enqueue(const SENTINEL_EVENT& evt,
                     const std::wstring& parentImagePath)
{
    if (!m_enabled) return;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push_back({evt, parentImagePath});
    }

    /* Wake the worker if batch threshold reached */
    if (m_queue.size() >= m_batchSize) {
        m_cv.notify_one();
    }
}

void
SiemWriter::Shutdown()
{
    if (!m_enabled) return;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
    }
    m_cv.notify_one();

    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }

    if (m_hSession) {
        WinHttpCloseHandle(m_hSession);
        m_hSession = nullptr;
    }

    m_enabled = false;
}

/* ── URL parsing ─────────────────────────────────────────────────────────── */

bool
SiemWriter::ParseEndpointUrl()
{
    /* Convert endpoint to wide string for WinHTTP */
    int wideLen = MultiByteToWideChar(CP_UTF8, 0,
                                       m_endpoint.c_str(), -1,
                                       nullptr, 0);
    if (wideLen <= 0) return false;

    std::wstring wideUrl(wideLen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, m_endpoint.c_str(), -1,
                        &wideUrl[0], wideLen);

    /* Parse URL components */
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);

    WCHAR hostBuf[256] = {};
    WCHAR pathBuf[1024] = {};

    urlComp.lpszHostName    = hostBuf;
    urlComp.dwHostNameLength = _countof(hostBuf);
    urlComp.lpszUrlPath     = pathBuf;
    urlComp.dwUrlPathLength = _countof(pathBuf);

    if (!WinHttpCrackUrl(wideUrl.c_str(), (DWORD)wideUrl.size(), 0, &urlComp)) {
        return false;
    }

    m_hostW   = hostBuf;
    m_pathW   = pathBuf;
    m_port    = urlComp.nPort;
    m_useHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    return true;
}

/* ── Worker thread ───────────────────────────────────────────────────────── */

void
SiemWriter::WorkerLoop()
{
    while (true) {
        std::deque<QueueEntry> batch;

        /* Wait for events or timeout */
        {
            std::unique_lock<std::mutex> lock(m_mutex);

            m_cv.wait_for(lock,
                std::chrono::seconds(m_flushIntervalSec),
                [this] {
                    return m_shutdown || m_queue.size() >= m_batchSize;
                });

            if (m_shutdown) {
                /* Shutting down — drain entire queue at once and exit */
                batch = std::move(m_queue);
            } else {
                /* Normal operation — drain up to batchSize events */
                size_t count = (std::min)((size_t)m_batchSize, m_queue.size());
                for (size_t i = 0; i < count; i++) {
                    batch.push_back(std::move(m_queue.front()));
                    m_queue.pop_front();
                }
            }
        }

        if (batch.empty()) {
            if (m_shutdown) break;
            continue;
        }

        /* Serialize batch to NDJSON */
        std::string ndjson;
        ndjson.reserve(batch.size() * 1024);

        for (const auto& entry : batch) {
            ndjson += SiemSerializeEvent(entry.evt, entry.parentImagePath,
                                          m_hostname, m_agentId);
            ndjson += '\n';
        }

        /* Try to drain spill file first (if any — skip during shutdown) */
        if (!m_shutdown) {
            DrainSpillFile();
        }

        /* POST the batch */
        if (!HttpPost(ndjson)) {
            SpillToDisk(ndjson);
        }

        if (m_shutdown) break;
    }

    /* Loop above already drained the queue on shutdown — nothing left. */

    std::printf("SentinelAgent: SIEM writer stopped\n");
}

/* ── HTTP POST ───────────────────────────────────────────────────────────── */

bool
SiemWriter::HttpPost(const std::string& ndjsonBatch)
{
    if (!m_hSession || ndjsonBatch.empty()) {
        return false;
    }

    /* Connect */
    HINTERNET hConnect = WinHttpConnect(
        m_hSession,
        m_hostW.c_str(),
        m_port,
        0);

    if (!hConnect) {
        std::printf("SentinelAgent: SIEM: WinHttpConnect failed (%lu)\n",
                    GetLastError());
        return false;
    }

    /* Open request */
    DWORD flags = m_useHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        m_pathW.c_str(),
        nullptr,            /* HTTP/1.1 */
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!hRequest) {
        std::printf("SentinelAgent: SIEM: WinHttpOpenRequest failed (%lu)\n",
                    GetLastError());
        WinHttpCloseHandle(hConnect);
        return false;
    }

    /* Set timeouts: 10s connect, 10s send, 15s receive */
    WinHttpSetTimeouts(hRequest, 10000, 10000, 10000, 15000);

    /* Add headers */
    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/x-ndjson\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!m_apiKey.empty()) {
        /* Build X-API-Key header */
        std::string hdr = "X-API-Key: " + m_apiKey + "\r\n";
        int wLen = MultiByteToWideChar(CP_UTF8, 0, hdr.c_str(), -1,
                                        nullptr, 0);
        std::wstring wHdr(wLen - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, hdr.c_str(), -1, &wHdr[0], wLen);

        WinHttpAddRequestHeaders(hRequest,
            wHdr.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    /* Send */
    BOOL ok = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)ndjsonBatch.c_str(),
        (DWORD)ndjsonBatch.size(),
        (DWORD)ndjsonBatch.size(),
        0);

    bool success = false;

    if (ok) {
        ok = WinHttpReceiveResponse(hRequest, nullptr);

        if (ok) {
            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &statusCode, &statusSize,
                WINHTTP_NO_HEADER_INDEX);

            if (statusCode >= 200 && statusCode < 300) {
                success = true;
            } else {
                std::printf("SentinelAgent: SIEM: HTTP %lu response\n",
                            statusCode);
            }
        }
    }

    if (!ok && !success) {
        std::printf("SentinelAgent: SIEM: HTTP POST failed (%lu)\n",
                    GetLastError());
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);

    return success;
}

/* ── Spill-to-disk ───────────────────────────────────────────────────────── */

void
SiemWriter::SpillToDisk(const std::string& ndjsonBatch)
{
    /* Check current spill file size */
    HANDLE hCheck = CreateFileA(
        m_spillPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    UINT64 currentSize = 0;
    if (hCheck != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER li;
        if (GetFileSizeEx(hCheck, &li)) {
            currentSize = li.QuadPart;
        }
        CloseHandle(hCheck);
    }

    if (currentSize + ndjsonBatch.size() > m_spillMaxBytes) {
        std::printf("SentinelAgent: SIEM: spill file full (%llu MB), "
                    "dropping %zu bytes\n",
                    currentSize / (1024 * 1024), ndjsonBatch.size());
        return;
    }

    /* Append to spill file */
    HANDLE hFile = CreateFileA(
        m_spillPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::printf("SentinelAgent: SIEM: failed to open spill file (%lu)\n",
                    GetLastError());
        return;
    }

    DWORD written = 0;
    WriteFile(hFile, ndjsonBatch.c_str(), (DWORD)ndjsonBatch.size(),
              &written, nullptr);
    CloseHandle(hFile);

    std::printf("SentinelAgent: SIEM: spilled %lu bytes to disk\n", written);
}

bool
SiemWriter::DrainSpillFile()
{
    /* Check if spill file exists and has data */
    DWORD attrs = GetFileAttributesA(m_spillPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return true;    /* No spill file — nothing to drain */
    }

    /* Read the entire spill file */
    std::ifstream ifs(m_spillPath, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        return true;
    }

    auto fileSize = ifs.tellg();
    if (fileSize <= 0) {
        ifs.close();
        return true;
    }

    ifs.seekg(0);
    std::string content((size_t)fileSize, '\0');
    ifs.read(&content[0], fileSize);
    ifs.close();

    /* POST the spill data */
    if (!HttpPost(content)) {
        return false;   /* Still can't reach SIEM — keep spill file */
    }

    /* Success — delete the spill file */
    DeleteFileA(m_spillPath.c_str());
    std::printf("SentinelAgent: SIEM: drained spill file (%lld bytes)\n",
                (long long)fileSize);

    return true;
}
