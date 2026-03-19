/*
 * sentinel-agent/output/siem_serializer.cpp
 * SIEM envelope serializer implementation.
 *
 * P9-T5: SIEM Integration.
 */

#include "siem_serializer.h"
#include "../json_writer.h"

std::string
SiemSerializeEvent(const SENTINEL_EVENT& evt,
                    const std::wstring& parentImagePath,
                    const std::string& hostname,
                    const std::string& agentId)
{
    /* Inner event JSON — reuse the shared serializer */
    std::string innerJson = JsonWriter::SerializeEvent(evt, parentImagePath);

    /* Build Appendix A envelope */
    std::string json;
    json.reserve(innerJson.size() + 256);

    json += "{\"schema\":\"sentinel/v1\"";

    json += ",\"host\":\"";
    json += JsonWriter::EscapeJson(hostname);
    json += "\"";

    json += ",\"agent_id\":\"";
    json += JsonWriter::EscapeJson(agentId);
    json += "\"";

    json += ",\"timestamp\":\"";
    json += JsonWriter::TimestampToIso8601(evt.Timestamp);
    json += "\"";

    json += ",\"event\":";
    json += innerJson;

    json += '}';

    return json;
}
