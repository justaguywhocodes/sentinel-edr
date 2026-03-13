/*
 * sentinel-agent/etw/provider_rpc.h
 * Parser for Microsoft-Windows-RPC ETW events.
 *
 * P7-T3: AMSI + RPC + Kernel-Process ETW Providers.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#ifndef SENTINEL_ETW_PROVIDER_RPC_H
#define SENTINEL_ETW_PROVIDER_RPC_H

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include "../../common/telemetry.h"

/*
 * Parse an RPC ETW event into a SENTINEL_EVENT.
 *
 * Handles:
 *   Event 5 — RpcClientCallStart (client initiates RPC call)
 *   Event 6 — RpcServerCallStart (server receives RPC call)
 *
 * Captures InterfaceUuid, OpNum, and Protocol for detecting lateral
 * movement via RPC (PsExec, WMI, service control, scheduled tasks).
 *
 * Returns true if the event was successfully parsed, false to skip.
 */
bool ParseRpcEvent(PEVENT_RECORD pEvent, SENTINEL_EVENT* outEvent);

#endif /* SENTINEL_ETW_PROVIDER_RPC_H */
