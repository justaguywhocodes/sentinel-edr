/*
 * sentinel-agent/etw/provider_dotnet.h
 * Parser for Microsoft-Windows-DotNETRuntime ETW events.
 *
 * P7-T1: ETW Consumer Framework + .NET Provider.
 */

#ifndef SENTINEL_ETW_PROVIDER_DOTNET_H
#define SENTINEL_ETW_PROVIDER_DOTNET_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include "telemetry.h"

/*
 * Parse a .NET Runtime ETW event into a SENTINEL_EVENT.
 *
 * Currently handles:
 *   - Event ID 154 (AssemblyLoad_V1): assembly loaded by the CLR
 *
 * Returns true if the event was successfully parsed and outEvent is populated.
 * Returns false if the event should be skipped (unknown event ID, parse error).
 */
bool ParseDotNetEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent);

#endif /* SENTINEL_ETW_PROVIDER_DOTNET_H */
