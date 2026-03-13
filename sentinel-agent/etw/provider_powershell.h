/*
 * sentinel-agent/etw/provider_powershell.h
 * Parser for Microsoft-Windows-PowerShell ETW events.
 *
 * P7-T2: DNS + PowerShell + Kerberos ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#ifndef SENTINEL_ETW_PROVIDER_POWERSHELL_H
#define SENTINEL_ETW_PROVIDER_POWERSHELL_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include "../../common/telemetry.h"

/*
 * Parse a PowerShell ETW event into a SENTINEL_EVENT.
 *
 * Handles:
 *   Event 4104 — Script block logged (ScriptBlockId, MessageNumber,
 *                MessageTotal, ScriptBlockText)
 *
 * Large scripts are split across multiple 4104 events. Each fragment is
 * captured individually — reassembly by ScriptBlockId is deferred to
 * post-processing.
 *
 * Returns true if the event was successfully parsed, false to skip.
 */
bool ParsePowerShellEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent);

#endif /* SENTINEL_ETW_PROVIDER_POWERSHELL_H */
