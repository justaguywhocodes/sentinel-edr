/*
 * akesoedr-agent/crossvalidation.h
 * P11-T5: Telemetry cross-validation (driver vs. ETW Kernel-Process).
 *
 * Correlates process creation events from two independent sources to
 * detect callback tampering or ETW session disruption.
 */

#ifndef AKESOEDR_CROSSVALIDATION_H
#define AKESOEDR_CROSSVALIDATION_H

#include <windows.h>
#include "telemetry.h"

class JsonWriter;

class CrossValidator {
public:
    /*
     * Initialize the cross-validator.
     * Pass a JsonWriter pointer for emitting tamper alerts.
     */
    void Init(JsonWriter* writer);

    /*
     * Called from EventProcessor::Process() for every event.
     * Tracks process creation from DriverProcess and ETW KernelProcess
     * sources and correlates them by PID.
     */
    void OnEvent(const AKESOEDR_EVENT& evt);

    /*
     * Periodic sweep — checks for unmatched entries older than the
     * correlation window. Call every ~10 seconds from the processing loop.
     */
    void Sweep();

private:
    static constexpr int    RING_SIZE       = 256;
    static constexpr LONGLONG MATCH_WINDOW_MS = 5000;   /* 5 second window */
    static constexpr LONGLONG STALE_MS        = 10000;  /* 10s before alert */

    struct CreateRecord {
        ULONG       pid;
        ULONGLONG   timestamp;  /* FILETIME as ULONGLONG */
        bool        matched;
        bool        valid;
    };

    CreateRecord m_driverCreates[RING_SIZE] = {};
    CreateRecord m_etwCreates[RING_SIZE]    = {};
    int          m_driverHead = 0;
    int          m_etwHead    = 0;

    JsonWriter*  m_pWriter    = nullptr;
    ULONGLONG    m_lastSweep  = 0;

    void RecordDriverCreate(ULONG pid, ULONGLONG timestamp);
    void RecordEtwCreate(ULONG pid, ULONGLONG timestamp);
    bool FindMatch(CreateRecord* ring, int size, ULONG pid, ULONGLONG timestamp);
    void EmitMismatchAlert(const char* detail, ULONG pid);
    ULONGLONG Now();
};

#endif /* AKESOEDR_CROSSVALIDATION_H */
