/*
 * akesoedr-agent/scanner/av_scanner.h
 * AkesoAV integration scanner.
 *
 * Wraps the edr_shim AVEngine and routes AV SIEM events into the
 * EDR's SiemWriter pipeline. On minifilter file events, runs AV scan
 * alongside YARA. Registers a SIEM callback so native AV events flow
 * to the SIEM with their own source_type ("akeso_av").
 */

#ifndef AKESOEDR_AV_SCANNER_H
#define AKESOEDR_AV_SCANNER_H

#include <windows.h>
#include "edr_shim.h"
#include "telemetry.h"

struct AkesoEDRConfig;
class SiemWriter;

class AVScanner {
public:
    /*
     * Initialize the AV scanner from EDR configuration.
     * siemWriter: pointer to the SiemWriter for raw event passthrough.
     * Returns true if AV engine loaded, false on graceful degradation.
     */
    bool Init(const AkesoEDRConfig& cfg, SiemWriter* siemWriter);

    /* Shut down AV engine. */
    void Shutdown();

    /* Whether the AV engine is loaded and available. */
    bool IsAvailable() const { return m_enabled && m_avEngine.av_available(); }

    /*
     * Scan a file on a minifilter event. Returns true if malware detected.
     * On detection, populates alertOut as an AkesoEDRSourceScanner event.
     */
    bool ScanFile(const AKESOEDR_FILE_EVENT& fileEvt,
                  AKESOEDR_EVENT& alertOut);

    /* Access the underlying AVEngine (for CLI status/version queries). */
    AVEngine& GetAVEngine() { return m_avEngine; }

private:
    AVEngine    m_avEngine;
    SiemWriter* m_siemWriter = nullptr;
    bool        m_enabled    = false;

    /* Dynamically resolved SIEM callback registration function */
    typedef int (*pfn_akav_set_siem_callback)(
        void* engine,
        void (*callback)(const void* event, void* user_data),
        void* user_data);
    pfn_akav_set_siem_callback m_fnSetSiemCallback = nullptr;

    /* Static callback dispatched from AV engine */
    static void SiemCallbackStatic(const void* event, void* user_data);
    void OnSiemEvent(const void* event);
};

#endif /* AKESOEDR_AV_SCANNER_H */
