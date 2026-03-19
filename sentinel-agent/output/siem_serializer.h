/*
 * sentinel-agent/output/siem_serializer.h
 * SIEM envelope serializer — wraps SENTINEL_EVENT in Appendix A format.
 *
 * The SIEM envelope adds host/agent identity context around the
 * standard event JSON so that a centralized SIEM can correlate
 * events across multiple endpoints.
 *
 * Envelope format (Appendix A):
 *   {
 *     "schema": "sentinel/v1",
 *     "host": "<hostname>",
 *     "agent_id": "<guid>",
 *     "timestamp": "<ISO8601>",
 *     "event": { <standard event JSON> }
 *   }
 *
 * P9-T5: SIEM Integration.
 */

#ifndef SENTINEL_SIEM_SERIALIZER_H
#define SENTINEL_SIEM_SERIALIZER_H

#include <string>
#include <windows.h>
#include "telemetry.h"

/*
 * Serialize a SENTINEL_EVENT into an Appendix A SIEM envelope.
 * Returns a single JSON object (no trailing newline).
 *
 * hostname:        machine hostname (cached by caller)
 * agentId:         agent instance GUID string (cached by caller)
 * parentImagePath: enriched parent process path (from ProcessTable)
 */
std::string SiemSerializeEvent(const SENTINEL_EVENT& evt,
                                const std::wstring& parentImagePath,
                                const std::string& hostname,
                                const std::string& agentId);

#endif /* SENTINEL_SIEM_SERIALIZER_H */
