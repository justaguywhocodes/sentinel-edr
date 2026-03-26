/*
 * akesoedr-agent/crossvalidation.cpp
 * P11-T5: Telemetry cross-validation implementation.
 *
 * Maintains two ring buffers of recent process creation events — one from
 * the kernel driver's PsSetCreateProcessNotifyRoutineEx callback, and one
 * from the ETW Microsoft-Windows-Kernel-Process provider. When an event
 * arrives from one source, we look for a matching PID in the other source's
 * buffer within a 5-second window.
 *
 * Unmatched entries after 10 seconds indicate that one telemetry source
 * has been tampered with:
 *   - Driver sees create but ETW doesn't → ETW session may have been killed
 *   - ETW sees create but driver doesn't → driver callback may have been
 *     removed (DKOM, PatchGuard bypass, etc.)
 */

#include "crossvalidation.h"
#include "json_writer.h"
#include <cstdio>
#include <cstring>

/* ── Helpers ────────────────────────────────────────────────────────────── */

ULONGLONG
CrossValidator::Now()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER li;
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return li.QuadPart;
}

void
CrossValidator::Init(JsonWriter* writer)
{
    m_pWriter   = writer;
    m_lastSweep = Now();
    memset(m_driverCreates, 0, sizeof(m_driverCreates));
    memset(m_etwCreates,    0, sizeof(m_etwCreates));
}

/* ── Record + match ─────────────────────────────────────────────────────── */

bool
CrossValidator::FindMatch(CreateRecord* ring, int size, ULONG pid, ULONGLONG timestamp)
{
    LONGLONG windowTicks = MATCH_WINDOW_MS * 10000LL;  /* ms → 100ns units */

    for (int i = 0; i < size; i++) {
        if (!ring[i].valid || ring[i].matched)
            continue;

        if (ring[i].pid == pid) {
            LONGLONG delta = (LONGLONG)(timestamp - ring[i].timestamp);
            if (delta < 0) delta = -delta;

            if (delta <= windowTicks) {
                ring[i].matched = true;
                return true;
            }
        }
    }
    return false;
}

void
CrossValidator::RecordDriverCreate(ULONG pid, ULONGLONG timestamp)
{
    /* Try to match against existing ETW entries */
    if (FindMatch(m_etwCreates, RING_SIZE, pid, timestamp))
        return;  /* Matched — both sources agree */

    /* No match yet — record for later correlation */
    m_driverCreates[m_driverHead].pid       = pid;
    m_driverCreates[m_driverHead].timestamp = timestamp;
    m_driverCreates[m_driverHead].matched   = false;
    m_driverCreates[m_driverHead].valid     = true;
    m_driverHead = (m_driverHead + 1) % RING_SIZE;
}

void
CrossValidator::RecordEtwCreate(ULONG pid, ULONGLONG timestamp)
{
    /* Try to match against existing driver entries */
    if (FindMatch(m_driverCreates, RING_SIZE, pid, timestamp))
        return;  /* Matched */

    /* No match yet — record */
    m_etwCreates[m_etwHead].pid       = pid;
    m_etwCreates[m_etwHead].timestamp = timestamp;
    m_etwCreates[m_etwHead].matched   = false;
    m_etwCreates[m_etwHead].valid     = true;
    m_etwHead = (m_etwHead + 1) % RING_SIZE;
}

/* ── Event dispatch ─────────────────────────────────────────────────────── */

void
CrossValidator::OnEvent(const AKESOEDR_EVENT& evt)
{
    ULONGLONG ts;
    ts = ((ULONGLONG)evt.Timestamp.HighPart << 32) | evt.Timestamp.LowPart;

    /* Driver process create event (source = DriverProcess, isCreate = true) */
    if (evt.Source == AkesoEDRSourceDriverProcess &&
        evt.Payload.Process.IsCreate) {
        RecordDriverCreate(evt.Payload.Process.NewProcessId, ts);
    }

    /* ETW Kernel-Process create event (eventId 1 = ProcessStart) */
    if (evt.Source == AkesoEDRSourceEtw &&
        evt.Payload.Etw.Provider == AkesoEDREtwKernelProc &&
        evt.Payload.Etw.EventId == 1) {
        RecordEtwCreate(evt.Payload.Etw.ProcessId, ts);
    }
}

/* ── Periodic sweep ─────────────────────────────────────────────────────── */

void
CrossValidator::Sweep()
{
    ULONGLONG now = Now();
    LONGLONG staleTicks = STALE_MS * 10000LL;

    /* Check driver entries that have no ETW match */
    for (int i = 0; i < RING_SIZE; i++) {
        if (!m_driverCreates[i].valid || m_driverCreates[i].matched)
            continue;

        LONGLONG age = (LONGLONG)(now - m_driverCreates[i].timestamp);
        if (age > staleTicks) {
            EmitMismatchAlert(
                "Driver saw process create but ETW did not (ETW session may be killed)",
                m_driverCreates[i].pid);
            m_driverCreates[i].valid = false;  /* Consume — don't re-alert */
        }
    }

    /* Check ETW entries that have no driver match */
    for (int i = 0; i < RING_SIZE; i++) {
        if (!m_etwCreates[i].valid || m_etwCreates[i].matched)
            continue;

        LONGLONG age = (LONGLONG)(now - m_etwCreates[i].timestamp);
        if (age > staleTicks) {
            EmitMismatchAlert(
                "ETW saw process create but driver did not (callback may be removed)",
                m_etwCreates[i].pid);
            m_etwCreates[i].valid = false;
        }
    }

    m_lastSweep = now;
}

/* ── Alert emission ─────────────────────────────────────────────────────── */

void
CrossValidator::EmitMismatchAlert(const char* detail, ULONG pid)
{
    if (!m_pWriter)
        return;

    AKESOEDR_EVENT evt = {};
    evt.Source   = AkesoEDRSourceSelfProtect;
    evt.Severity = AkesoEDRSeverityHigh;
    CoCreateGuid(&evt.EventId);

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    evt.Timestamp.LowPart  = ft.dwLowDateTime;
    evt.Timestamp.HighPart = ft.dwHighDateTime;

    evt.Payload.Tamper.TamperType = AkesoEDRTamperCallbackRemoved;
    evt.Payload.Tamper.ProcessId  = pid;

    MultiByteToWideChar(CP_ACP, 0, detail, -1,
                        evt.Payload.Tamper.Detail, AKESOEDR_MAX_PATH);

    m_pWriter->WriteEvent(evt, L"");

    std::printf("AkesoEDRAgent: CROSS-VAL ALERT: PID %lu — %s\n", pid, detail);
}
