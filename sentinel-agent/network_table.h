/*
 * sentinel-agent/network_table.h
 * In-memory connection table for network event aggregation.
 *
 * Maintains a map of {RemoteAddr, RemotePort, Protocol} → ConnectionEntry,
 * updated from SENTINEL_NETWORK_EVENT telemetry. Each entry tracks connection
 * count, first/last seen timestamps, and the set of PIDs that connected to
 * that destination.
 *
 * Thread-safe via std::mutex (same pattern as ProcessTable).
 *
 * P6-T3: Connection Table.
 */

#ifndef SENTINEL_NETWORK_TABLE_H
#define SENTINEL_NETWORK_TABLE_H

#include <windows.h>
#include <set>
#include <vector>
#include <unordered_map>
#include <mutex>
#include "telemetry.h"

/* ── Connection key (composite map key) ─────────────────────────────────── */

struct ConnectionKey {
    ULONG   RemoteAddr;     /* IPv4 address */
    USHORT  RemotePort;
    ULONG   Protocol;       /* IPPROTO_TCP (6), IPPROTO_UDP (17) */

    bool operator==(const ConnectionKey& other) const {
        return RemoteAddr == other.RemoteAddr
            && RemotePort == other.RemotePort
            && Protocol  == other.Protocol;
    }
};

/* Hash specialization for ConnectionKey */
namespace std {
    template<>
    struct hash<ConnectionKey> {
        size_t operator()(const ConnectionKey& k) const {
            size_t h = hash<ULONG>()(k.RemoteAddr);
            h ^= hash<USHORT>()(k.RemotePort) << 1;
            h ^= hash<ULONG>()(k.Protocol) << 2;
            return h;
        }
    };
}

/* ── Connection entry (aggregated record) ───────────────────────────────── */

struct ConnectionEntry {
    /* Identity */
    ULONG       RemoteAddr;
    USHORT      RemotePort;
    ULONG       Protocol;

    /* Tracking */
    ULONGLONG       ConnectionCount;
    LARGE_INTEGER   FirstSeen;
    LARGE_INTEGER   LastSeen;
    ULONGLONG       TotalBytes;     /* Placeholder — WFP ALE doesn't provide byte counts */

    /* Process association */
    std::set<ULONG> Pids;
};

/* ── Network table ──────────────────────────────────────────────────────── */

class NetworkTable {
public:
    /*
     * Update the table from a network event.
     * Ignores non-network events (source != SentinelSourceDriverNetwork).
     * Upserts the connection entry keyed by {RemoteAddr, RemotePort, Protocol}.
     */
    void OnNetworkEvent(const SENTINEL_EVENT& evt);

    /*
     * Get a thread-safe snapshot of all connection entries.
     * Entries are sorted by ConnectionCount descending (most active first).
     */
    void GetSnapshot(std::vector<ConnectionEntry>& out);

    /* Number of unique connections tracked. */
    size_t Size();

    /*
     * Print a formatted connection table summary to stdout.
     * Intended for periodic console output.
     */
    void PrintSummary();

private:
    std::unordered_map<ConnectionKey, ConnectionEntry> m_entries;
    std::mutex m_mutex;
};

#endif /* SENTINEL_NETWORK_TABLE_H */
