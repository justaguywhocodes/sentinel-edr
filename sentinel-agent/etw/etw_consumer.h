/*
 * sentinel-agent/etw/etw_consumer.h
 * ETW (Event Tracing for Windows) consumer framework.
 *
 * Creates a real-time trace session, enables ETW providers, and processes
 * events in a dedicated consumer thread. Events are converted to
 * SENTINEL_EVENT and pushed into the agent's EventQueue.
 *
 * P7-T1: ETW Consumer Framework + .NET Provider.
 * Book reference: Chapter 8 — Event Tracing for Windows.
 */

#ifndef SENTINEL_ETW_CONSUMER_H
#define SENTINEL_ETW_CONSUMER_H

#include <windows.h>

/*
 * Initialize the ETW consumer:
 *   - Clean up any stale session from a previous crash
 *   - Create a real-time trace session
 *   - Enable configured ETW providers (currently: DotNETRuntime)
 *
 * Must be called before EtwConsumerStart().
 * Requires administrator/SYSTEM privileges.
 *
 * Returns true on success, false on failure (logged via AgentLog).
 */
bool EtwConsumerInit();

/*
 * Start the ETW consumer thread.
 * The thread blocks on ProcessTrace(), processing events as they arrive.
 * Events are converted to SENTINEL_EVENT and pushed to g_EventQueue.
 *
 * Must be called after EtwConsumerInit().
 */
void EtwConsumerStart();

/*
 * Stop the ETW consumer:
 *   - Stop the trace session (unblocks ProcessTrace)
 *   - Join the consumer thread
 *   - Clean up handles
 *
 * Safe to call even if Init/Start were not called.
 */
void EtwConsumerStop();

#endif /* SENTINEL_ETW_CONSUMER_H */
