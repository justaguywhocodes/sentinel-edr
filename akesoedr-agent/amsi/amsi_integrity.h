/*
 * akesoedr-agent/amsi/amsi_integrity.h
 * P11-T4: AMSI bypass detection via AmsiScanBuffer integrity check.
 */

#ifndef AKESOEDR_AMSI_INTEGRITY_H
#define AKESOEDR_AMSI_INTEGRITY_H

#include "json_writer.h"

/*
 * Start the AMSI integrity monitor.
 * Captures baseline bytes of AmsiScanBuffer and starts a background
 * thread that checks every 10 seconds for patches.
 * Pass a pointer to the JsonWriter for tamper alert logging.
 */
void AmsiIntegrityInit(JsonWriter* writer);

/* Stop the monitor thread and release resources. */
void AmsiIntegrityShutdown();

#endif /* AKESOEDR_AMSI_INTEGRITY_H */
