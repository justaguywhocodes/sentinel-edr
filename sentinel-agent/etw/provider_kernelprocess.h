/*
 * sentinel-agent/etw/provider_kernelprocess.h
 * Parser for Microsoft-Windows-Kernel-Process ETW events.
 *
 * P7-T3: AMSI + RPC + Kernel-Process ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#ifndef SENTINEL_ETW_PROVIDER_KERNELPROCESS_H
#define SENTINEL_ETW_PROVIDER_KERNELPROCESS_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include "../../common/telemetry.h"

/*
 * Parse a Kernel-Process ETW event into a SENTINEL_EVENT.
 *
 * Handles:
 *   Event 1 — ProcessStart (creation: PID, PPID, SessionId, ImageName)
 *   Event 2 — ProcessStop  (termination: PID, ExitCode, ImageName)
 *
 * Provides redundant process telemetry that cross-validates against
 * the minifilter driver's PsSetCreateProcessNotifyRoutineEx callbacks.
 * Same PID + similar timestamp = confirmed; mismatch = evasion indicator.
 *
 * Returns true if the event was successfully parsed, false to skip.
 */
bool ParseKernelProcessEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent);

#endif /* SENTINEL_ETW_PROVIDER_KERNELPROCESS_H */
