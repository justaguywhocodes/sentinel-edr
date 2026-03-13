/*
 * sentinel-agent/etw/provider_kerberos.h
 * Parser for Microsoft-Windows-Security-Kerberos ETW events.
 *
 * P7-T2: DNS + PowerShell + Kerberos ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#ifndef SENTINEL_ETW_PROVIDER_KERBEROS_H
#define SENTINEL_ETW_PROVIDER_KERBEROS_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include "../../common/telemetry.h"

/*
 * Parse a Kerberos ETW event into a SENTINEL_EVENT.
 *
 * Handles:
 *   Event 14 — TGS (service ticket) request
 *   Event  4 — TGT (initial authentication) request
 *
 * Detects Kerberoasting, Golden Ticket usage, and lateral movement
 * via service ticket abuse.
 *
 * Returns true if the event was successfully parsed, false to skip.
 */
bool ParseKerberosEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent);

#endif /* SENTINEL_ETW_PROVIDER_KERBEROS_H */
