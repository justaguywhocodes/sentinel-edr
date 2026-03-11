/*
 * sentinel-agent/service.h
 * Windows service framework for the SentinelPOC agent.
 *
 * The agent runs as a Windows service (SERVICE_WIN32_OWN_PROCESS).
 * ServiceMain is registered with the SCM via StartServiceCtrlDispatcher.
 * The --console flag bypasses the SCM for debugging.
 */

#ifndef SENTINEL_SERVICE_H
#define SENTINEL_SERVICE_H

#include <windows.h>

/*
 * ServiceMain — SCM entry point.
 * Registered via SERVICE_TABLE_ENTRY in main().
 */
void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

/*
 * RunConsoleMode — Run the agent as a console application for debugging.
 * Ctrl+C triggers graceful shutdown.
 */
void RunConsoleMode();

#endif /* SENTINEL_SERVICE_H */
