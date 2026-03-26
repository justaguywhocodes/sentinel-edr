/*
 * akesoedr-agent/event_processor.cpp
 * Event processing orchestrator implementation.
 *
 * P4-T2: Event Processing & JSON Logging.
 * P4-T3: Single-Event Rule Engine.
 * P4-T4: Sequence Rule Engine.
 * P4-T5: Threshold Rule Engine.
 */

#include "event_processor.h"
#include "rules/rule_validator.h"
#include <cstdio>
#include <cstring>
#include <vector>

/* ── Init / Shutdown ─────────────────────────────────────────────────────── */

bool
EventProcessor::Init(const AkesoEDRConfig& cfg)
{
    m_config = cfg;
    m_eventsProcessed = 0;

    /* Load detection rules from configured directory */
    m_ruleEngine.Init(m_config.rulesDir);
    m_sequenceEngine.Init(m_config.rulesDir);
    m_thresholdEngine.Init(m_config.rulesDir);

    /* Initialize YARA scanner with configured directory and max file size */
    if (!m_yaraScanner.Init(m_config.yaraRulesDir, m_config.scanMaxFileSize)) {
        std::printf("AkesoEDRAgent: WARNING: YARA scanner init failed\n");
    }

    /* Initialize on-access scanner with configured cache TTL */
    m_onAccessScanner.Init(&m_yaraScanner, m_config.scanCacheTtlSec);

    /* Initialize memory scanner with configured max region size */
    m_memoryScanner.Init(&m_yaraScanner, m_config.scanMaxRegionSize);

    /* Initialize SIEM output writer (P9-T5) */
    m_siemWriter.Init(m_config);

    /* Initialize cross-validator (P11-T5) */
    m_crossValidator.Init(&m_jsonWriter);

    /* Open JSON log with configured max size for rotation */
    return m_jsonWriter.Open(m_config.logPath, m_config.logMaxSizeBytes);
}

void
EventProcessor::Shutdown()
{
    m_siemWriter.Shutdown();
    m_memoryScanner.Shutdown();
    m_onAccessScanner.Shutdown();
    m_yaraScanner.Shutdown();
    m_jsonWriter.Close();
}

/* ── Process ─────────────────────────────────────────────────────────────── */

void
EventProcessor::Process(const AKESOEDR_EVENT& evt)
{
    m_eventsProcessed++;

    /* 1. Update process table from this event */
    m_processTable.OnEvent(evt);

    /* 1b. Update connection table from network events */
    m_networkTable.OnNetworkEvent(evt);

    /* 1c. Cross-validate driver vs ETW process creation (P11-T5) */
    m_crossValidator.OnEvent(evt);
    if (m_eventsProcessed % 1000 == 0) {
        m_crossValidator.Sweep();
    }

    /* 1c. On-access YARA scan for minifilter file events (P8-T2) */
    if (evt.Source == AkesoEDRSourceDriverMinifilter) {
        AKESOEDR_EVENT scanAlert = {};
        if (m_onAccessScanner.OnFileEvent(evt.Payload.File, scanAlert)) {
            m_eventsProcessed++;
            std::wstring scanParent = m_processTable.GetParentImagePath(scanAlert);
            m_jsonWriter.WriteEvent(scanAlert, scanParent);
            PrintSummary(scanAlert);
        }
    }

    /* 2. Evaluate single-event detection rules */
    std::vector<AKESOEDR_EVENT> alerts;
    m_ruleEngine.Evaluate(evt, m_processTable, alerts);

    /* 3. Evaluate sequence detection rules */
    m_sequenceEngine.Evaluate(evt, m_processTable, alerts);

    /* 4. Evaluate threshold detection rules */
    m_thresholdEngine.Evaluate(evt, m_processTable, alerts);

    /* 5. Enrich: look up parent image path */
    std::wstring parentImagePath = m_processTable.GetParentImagePath(evt);

    /* 6. Write JSON to log file */
    m_jsonWriter.WriteEvent(evt, parentImagePath);

    /* 6b. Send to SIEM output (P9-T5) */
    m_siemWriter.Enqueue(evt, parentImagePath);

    /* 7. Print summary to stdout for console mode */
    PrintSummary(evt);

    /* 8. Process alert events (write to log + print + history) */
    for (const auto& alert : alerts) {
        m_eventsProcessed++;
        std::wstring alertParent = m_processTable.GetParentImagePath(alert);
        m_jsonWriter.WriteEvent(alert, alertParent);

        std::printf("  ** ALERT: [%s] rule=%s trigger=%s pid=%lu\n",
                    SeverityName(alert.Severity),
                    alert.Payload.Alert.RuleName,
                    SourceName(alert.Payload.Alert.TriggerSource),
                    alert.ProcessCtx.ProcessId);

        RecordAlert(alert);
    }

    /* 9. Trigger memory scan on shellcode sequence alerts (P8-T3).
     *    When the sequence rule detects alloc(RW) → protect(RX) → create_thread,
     *    scan the offending process for unbacked executable memory regions. */
    for (const auto& alert : alerts) {
        if (alert.Source == AkesoEDRSourceRuleEngine &&
            std::strstr(alert.Payload.Alert.RuleName, "Shellcode") != nullptr) {
            AKESOEDR_EVENT memAlert = {};
            if (m_memoryScanner.ScanProcess(
                    alert.ProcessCtx.ProcessId, memAlert)) {
                m_eventsProcessed++;
                std::wstring memParent =
                    m_processTable.GetParentImagePath(memAlert);
                m_jsonWriter.WriteEvent(memAlert, memParent);
                PrintSummary(memAlert);
            }
        }
    }
}

/* ── Console summary ─────────────────────────────────────────────────────── */

void
EventProcessor::PrintSummary(const AKESOEDR_EVENT& evt)
{
    if (evt.Source == AkesoEDRSourceHookDll) {
        /*
         * Suppress per-event hook DLL output — too noisy with
         * NtAllocateVirtualMemory firing hundreds of times per second
         * for normal .NET / browser processes.  Alerts generated by
         * the rule engine are still printed separately.
         * Events are still logged to the JSON file.
         */
    } else if (evt.Source == AkesoEDRSourceDriverMinifilter) {
        /*
         * Suppress per-event minifilter output — too noisy with every
         * system-wide file I/O generating an event.  On-access scanner
         * alerts (AkesoEDRSourceScanner) are still printed below.
         * Events are still logged to the JSON file.
         */
    } else if (evt.Source == AkesoEDRSourceDriverPipe) {
        const auto& pipe = evt.Payload.Pipe;
        std::printf("[%llu] source=%s PIPE_CREATE pid=%lu pipe=%S%s\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    pipe.CreatingProcessId,
                    pipe.PipeName,
                    pipe.IsSuspicious ? " [SUSPICIOUS]" : "");
    } else if (evt.Source == AkesoEDRSourceDriverNetwork) {
        /*
         * Suppress per-event network output — too noisy with WFP firing
         * hundreds of events per second. The periodic connection table
         * dump (every 30s) provides the same data in aggregate form.
         * Events are still logged to the JSON file.
         */
    } else if (evt.Source == AkesoEDRSourceEtw) {
        const auto& etw = evt.Payload.Etw;
        if (etw.Provider == AkesoEDREtwDotNet) {
            std::printf("[%llu] source=%s provider=DotNet eventId=%u pid=%lu assembly=%S\n",
                        m_eventsProcessed,
                        SourceName(evt.Source),
                        etw.EventId,
                        etw.ProcessId,
                        etw.u.DotNet.AssemblyName);
        } else if (etw.Provider == AkesoEDREtwDnsClient) {
            std::printf("[%llu] source=%s provider=DnsClient eventId=%u pid=%lu query=%S type=%u status=%lu\n",
                        m_eventsProcessed,
                        SourceName(evt.Source),
                        etw.EventId,
                        etw.ProcessId,
                        etw.u.Dns.QueryName,
                        etw.u.Dns.QueryType,
                        etw.u.Dns.QueryStatus);
        } else if (etw.Provider == AkesoEDREtwPowerShell) {
            /* Extract Command Name from the context block for concise output */
            WCHAR cmdName[256] = {};
            const WCHAR* search = wcsstr(etw.u.PowerShell.ScriptBlock, L"Command Name");
            if (search) {
                /* Skip "Command Name = " */
                const WCHAR* eq = wcsstr(search, L"= ");
                if (eq) {
                    eq += 2;
                    size_t i = 0;
                    while (i < 255 && eq[i] != L'\0' && eq[i] != L'\r' && eq[i] != L'\n') {
                        cmdName[i] = eq[i]; i++;
                    }
                    cmdName[i] = L'\0';
                }
            }
            if (cmdName[0] == L'\0') wcscpy_s(cmdName, 256, L"(unknown)");

            std::printf("[%llu] source=%s provider=PowerShell eventId=%u pid=%lu cmd=%S\n",
                        m_eventsProcessed,
                        SourceName(evt.Source),
                        etw.EventId,
                        etw.ProcessId,
                        cmdName);
        } else if (etw.Provider == AkesoEDREtwKerberos) {
            std::printf("[%llu] source=%s provider=Kerberos eventId=%u pid=%lu target=%S status=%lu\n",
                        m_eventsProcessed,
                        SourceName(evt.Source),
                        etw.EventId,
                        etw.ProcessId,
                        etw.u.Kerberos.TargetName,
                        etw.u.Kerberos.Status);
        } else if (etw.Provider == AkesoEDREtwRpc) {
            /*
             * Suppress per-event RPC output — too noisy with dozens of
             * RPC calls per second from normal system activity.  Alerts
             * generated by the rule engine are still printed separately.
             * Events are still logged to the JSON file.
             */
        } else if (etw.Provider == AkesoEDREtwKernelProc) {
            if (etw.EventId == 1) {
                std::printf("[%llu] source=%s provider=KernelProcess eventId=%u pid=%lu ppid=%lu image=%S\n",
                            m_eventsProcessed,
                            SourceName(evt.Source),
                            etw.EventId,
                            etw.ProcessId,
                            etw.u.KernelProcess.ParentProcessId,
                            etw.u.KernelProcess.ImageName);
            } else {
                std::printf("[%llu] source=%s provider=KernelProcess eventId=%u pid=%lu exitCode=%lu image=%S\n",
                            m_eventsProcessed,
                            SourceName(evt.Source),
                            etw.EventId,
                            etw.ProcessId,
                            etw.u.KernelProcess.ExitCode,
                            etw.u.KernelProcess.ImageName);
            }
        } else {
            std::printf("[%llu] source=%s provider=%d eventId=%u pid=%lu\n",
                        m_eventsProcessed,
                        SourceName(evt.Source),
                        etw.Provider,
                        etw.EventId,
                        etw.ProcessId);
        }
    } else if (evt.Source == AkesoEDRSourceAmsi) {
        const auto& amsi = evt.Payload.Amsi;
        std::printf("[%llu] source=%s appName=%S scanResult=%d contentSize=%lu\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    amsi.AppName,
                    amsi.ScanResult,
                    amsi.ContentSize);
    } else if (evt.Source == AkesoEDRSourceScanner) {
        const auto& scan = evt.Payload.Scanner;
        static const char* scanTypeNames[] = { "OnAccess", "OnDemand", "Memory" };
        const char* typeName = (scan.ScanType >= 0 && scan.ScanType <= 2)
            ? scanTypeNames[scan.ScanType] : "Unknown";
        std::printf("[%llu] source=%s type=%s path=%S match=%s rule=%s\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    typeName,
                    scan.TargetPath,
                    scan.IsMatch ? "YES" : "no",
                    scan.IsMatch ? scan.YaraRule : "(none)");
    } else if (evt.Source == AkesoEDRSourceDriverThread  ||
               evt.Source == AkesoEDRSourceDriverImageLoad ||
               evt.Source == AkesoEDRSourceDriverRegistry) {
        /*
         * Suppress per-event thread/image-load/registry output — extremely
         * high volume from normal system activity.  Alerts generated by
         * the rule engine are still printed separately.
         * Events are still logged to the JSON file.
         */
    } else if (evt.Source == AkesoEDRSourceDriverProcess) {
        const auto& proc = evt.Payload.Process;
        std::printf("[%llu] source=%s %s pid=%lu ppid=%lu\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    proc.IsCreate ? "CREATE" : "EXIT",
                    proc.NewProcessId,
                    proc.ParentProcessId);
    } else {
        std::printf("[%llu] source=%s pid=%lu\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    evt.ProcessCtx.ProcessId);
    }
}

/* ── P9-T1: CLI command support ─────────────────────────────────────────── */

void
EventProcessor::RecordAlert(const AKESOEDR_EVENT& alert)
{
    std::lock_guard<std::mutex> lock(m_alertMutex);
    m_alertHistory.push_back(alert);
    while (m_alertHistory.size() > ALERT_HISTORY_MAX) {
        m_alertHistory.pop_front();
    }
}

std::deque<AKESOEDR_EVENT>
EventProcessor::GetAlertHistory()
{
    std::lock_guard<std::mutex> lock(m_alertMutex);
    return m_alertHistory;     /* Return a copy (thread-safe) */
}

RuleCountSummary
EventProcessor::GetRuleCounts() const
{
    return {
        m_ruleEngine.RuleCount(),
        m_sequenceEngine.RuleCount(),
        m_thresholdEngine.RuleCount(),
        m_yaraScanner.RuleCount()
    };
}

bool
EventProcessor::ReloadRules()
{
    bool ok = true;

    m_ruleEngine.Init(m_config.rulesDir);
    m_sequenceEngine.Init(m_config.rulesDir);
    m_thresholdEngine.Init(m_config.rulesDir);

    std::printf("AkesoEDRAgent: Rules reloaded — single=%zu seq=%zu thr=%zu\n",
                m_ruleEngine.RuleCount(),
                m_sequenceEngine.RuleCount(),
                m_thresholdEngine.RuleCount());

    return ok;
}

RulesUpdateResult
EventProcessor::ValidateAndReloadRules()
{
    RulesUpdateResult res = {};

    /* Phase 1: Validate detection rules (dry-run parse) */
    ValidationResult detResult = ValidateDetectionRules(m_config.rulesDir);
    if (!detResult.success) {
        res.validated = false;
        res.error     = detResult.error;
        return res;
    }

    /* Phase 2: Validate YARA rules (dry-run compile) */
    ValidationResult yaraResult = ValidateYaraRules(m_config.yaraRulesDir);
    if (!yaraResult.success) {
        res.validated = false;
        res.error     = yaraResult.error;
        return res;
    }

    res.validated = true;

    /* Phase 3: Reload — detection rules */
    ReloadRules();

    /* Phase 4: Reload — YARA rules (atomic swap) */
    m_yaraScanner.Reload();

    res.reloaded       = true;
    res.singleCount    = (int)m_ruleEngine.RuleCount();
    res.sequenceCount  = (int)m_sequenceEngine.RuleCount();
    res.thresholdCount = (int)m_thresholdEngine.RuleCount();
    res.yaraCount      = m_yaraScanner.RuleCount();

    std::printf("AkesoEDRAgent: Rules update — validated and reloaded "
                "(single=%d seq=%d thr=%d yara=%d)\n",
                res.singleCount, res.sequenceCount,
                res.thresholdCount, res.yaraCount);

    return res;
}

bool
EventProcessor::ScanFileOnDemand(const wchar_t* path,
                                 AKESOEDR_SCANNER_EVENT& result)
{
    return m_yaraScanner.ScanFile(path, AkesoEDRScanOnDemand, result);
}
