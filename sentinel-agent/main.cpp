/*
 * sentinel-agent/main.cpp
 * User-mode agent service entry point.
 *
 * Two modes:
 *   1. Service mode (default): Registers with the SCM and runs as a
 *      Windows service (SERVICE_WIN32_OWN_PROCESS).
 *   2. Console mode (--console): Runs interactively for debugging.
 *      Ctrl+C triggers graceful shutdown.
 *
 * P4-T1: Service skeleton + event pipeline.
 */

#include <windows.h>
#include <cstdio>
#include <cstring>
#include "service.h"
#include "constants.h"

int
main(int argc, char* argv[])
{
    /* Check for --console flag */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--console") == 0) {
            std::printf("SentinelPOC Agent v%s\n", SENTINEL_VERSION);
            RunConsoleMode();
            return 0;
        }
    }

    /* Service mode — register with the SCM */
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { (LPWSTR)SENTINEL_AGENT_SERVICE, ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* Not running as a service — show usage */
            std::printf("SentinelPOC Agent v%s\n", SENTINEL_VERSION);
            std::printf("Usage:\n");
            std::printf("  sentinel-agent.exe --console    "
                        "Run interactively (for debugging)\n");
            std::printf("  sc create SentinelAgent binPath= "
                        "\"<path>\\sentinel-agent.exe\"\n");
            std::printf("  sc start SentinelAgent           "
                        "Start as a Windows service\n");
            return 1;
        }
        std::fprintf(stderr, "StartServiceCtrlDispatcher failed: %lu\n", err);
        return 1;
    }

    return 0;
}
