/*
 * sentinel-agent/network_table.cpp
 * In-memory connection table implementation.
 *
 * Aggregates SENTINEL_NETWORK_EVENT telemetry into connection entries
 * keyed by {RemoteAddr, RemotePort, Protocol}. Each entry tracks how
 * many times a connection was seen, when it was first/last observed,
 * and which PIDs initiated the connection.
 *
 * P6-T3: Connection Table.
 */

#include "network_table.h"
#include <cstdio>
#include <algorithm>

/* ── Helper: format IPv4 address to dotted decimal ─────────────────────── */

static void
FormatIPv4(ULONG addr, char* buf, size_t bufLen)
{
    /*
     * WFP stores IPv4 in host byte order on x86 (little-endian).
     * Byte extraction matches json_writer.cpp pattern.
     */
    _snprintf_s(buf, bufLen, _TRUNCATE,
        "%u.%u.%u.%u",
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >>  8) & 0xFF,
         addr        & 0xFF);
}

/* ── Helper: format LARGE_INTEGER timestamp ────────────────────────────── */

static void
FormatTimestamp(const LARGE_INTEGER& ts, char* buf, size_t bufLen)
{
    FILETIME    ft;
    SYSTEMTIME  st;

    ft.dwLowDateTime  = ts.LowPart;
    ft.dwHighDateTime = (DWORD)ts.HighPart;

    if (FileTimeToSystemTime(&ft, &st)) {
        _snprintf_s(buf, bufLen, _TRUNCATE,
            "%04d-%02d-%02d %02d:%02d:%02d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
    } else {
        _snprintf_s(buf, bufLen, _TRUNCATE, "(unknown)");
    }
}

/* ── Helper: protocol number to name ───────────────────────────────────── */

static const char*
ProtocolName(ULONG proto)
{
    switch (proto) {
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "???";
    }
}

/* ── OnNetworkEvent ────────────────────────────────────────────────────── */

void
NetworkTable::OnNetworkEvent(const SENTINEL_EVENT& evt)
{
    /* Only process network events */
    if (evt.Source != SentinelSourceDriverNetwork) {
        return;
    }

    const auto& net = evt.Payload.Network;

    ConnectionKey key = {};
    key.RemoteAddr = net.RemoteAddr;
    key.RemotePort = net.RemotePort;
    key.Protocol   = net.Protocol;

    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_entries.find(key);
    if (it != m_entries.end()) {
        /* Existing connection — update */
        it->second.ConnectionCount++;
        it->second.LastSeen = evt.Timestamp;
        if (net.ProcessId != 0) {
            it->second.Pids.insert(net.ProcessId);
        }
    } else {
        /* New connection */
        ConnectionEntry entry = {};
        entry.RemoteAddr      = net.RemoteAddr;
        entry.RemotePort      = net.RemotePort;
        entry.Protocol        = net.Protocol;
        entry.ConnectionCount = 1;
        entry.FirstSeen       = evt.Timestamp;
        entry.LastSeen        = evt.Timestamp;
        entry.TotalBytes      = 0;
        if (net.ProcessId != 0) {
            entry.Pids.insert(net.ProcessId);
        }

        m_entries[key] = std::move(entry);
    }
}

/* ── GetSnapshot ───────────────────────────────────────────────────────── */

void
NetworkTable::GetSnapshot(std::vector<ConnectionEntry>& out)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    out.clear();
    out.reserve(m_entries.size());

    for (const auto& pair : m_entries) {
        out.push_back(pair.second);
    }

    /* Sort by connection count descending (most active first) */
    std::sort(out.begin(), out.end(),
        [](const ConnectionEntry& a, const ConnectionEntry& b) {
            return a.ConnectionCount > b.ConnectionCount;
        });
}

/* ── Size ──────────────────────────────────────────────────────────────── */

size_t
NetworkTable::Size()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_entries.size();
}

/* ── PrintSummary ──────────────────────────────────────────────────────── */

void
NetworkTable::PrintSummary()
{
    std::vector<ConnectionEntry> snapshot;
    GetSnapshot(snapshot);

    if (snapshot.empty()) {
        return;
    }

    std::printf("\n=== Connection Table (%zu entries) ===\n", snapshot.size());
    std::printf("%-18s %5s %5s %7s  %-12s  %-20s  %-20s\n",
        "Remote IP", "Port", "Proto", "Count", "PIDs", "First Seen", "Last Seen");
    std::printf("%-18s %5s %5s %7s  %-12s  %-20s  %-20s\n",
        "------------------", "-----", "-----", "-------",
        "------------", "--------------------", "--------------------");

    /* Show top 25 connections to keep output manageable */
    size_t limit = (snapshot.size() < 25) ? snapshot.size() : 25;

    for (size_t i = 0; i < limit; i++) {
        const auto& conn = snapshot[i];

        char ipBuf[32];
        FormatIPv4(conn.RemoteAddr, ipBuf, sizeof(ipBuf));

        char firstBuf[32];
        FormatTimestamp(conn.FirstSeen, firstBuf, sizeof(firstBuf));

        char lastBuf[32];
        FormatTimestamp(conn.LastSeen, lastBuf, sizeof(lastBuf));

        /* Format PIDs list (show first 3, then "..." if more) */
        char pidBuf[64] = {};
        size_t pidOff = 0;
        int pidCount = 0;
        for (auto pid : conn.Pids) {
            if (pidCount >= 3) {
                pidOff += _snprintf_s(pidBuf + pidOff,
                    sizeof(pidBuf) - pidOff, _TRUNCATE, ",...");
                break;
            }
            if (pidCount > 0) {
                pidOff += _snprintf_s(pidBuf + pidOff,
                    sizeof(pidBuf) - pidOff, _TRUNCATE, ",");
            }
            pidOff += _snprintf_s(pidBuf + pidOff,
                sizeof(pidBuf) - pidOff, _TRUNCATE, "%lu", pid);
            pidCount++;
        }

        std::printf("%-18s %5u %5s %7llu  %-12s  %-20s  %-20s\n",
            ipBuf,
            conn.RemotePort,
            ProtocolName(conn.Protocol),
            conn.ConnectionCount,
            pidBuf,
            firstBuf,
            lastBuf);
    }

    if (snapshot.size() > limit) {
        std::printf("  ... and %zu more connections\n",
            snapshot.size() - limit);
    }

    std::printf("\n");
    std::fflush(stdout);
}
