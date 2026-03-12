/*
 * sentinel-agent/event_processor.cpp
 * Event processing orchestrator implementation.
 *
 * P4-T2: Event Processing & JSON Logging.
 * P4-T3: Single-Event Rule Engine.
 * P4-T4: Sequence Rule Engine.
 * P4-T5: Threshold Rule Engine.
 */

#include "event_processor.h"
#include <cstdio>
#include <vector>

/* ── Init / Shutdown ─────────────────────────────────────────────────────── */

bool
EventProcessor::Init(const char* logPath)
{
    m_eventsProcessed = 0;

    /* Load detection rules */
    m_ruleEngine.Init("C:\\SentinelPOC\\rules");
    m_sequenceEngine.Init("C:\\SentinelPOC\\rules");
    m_thresholdEngine.Init("C:\\SentinelPOC\\rules");

    return m_jsonWriter.Open(logPath);
}

void
EventProcessor::Shutdown()
{
    m_jsonWriter.Close();
}

/* ── Process ─────────────────────────────────────────────────────────────── */

void
EventProcessor::Process(const SENTINEL_EVENT& evt)
{
    m_eventsProcessed++;

    /* 1. Update process table from this event */
    m_processTable.OnEvent(evt);

    /* 2. Evaluate single-event detection rules */
    std::vector<SENTINEL_EVENT> alerts;
    m_ruleEngine.Evaluate(evt, m_processTable, alerts);

    /* 3. Evaluate sequence detection rules */
    m_sequenceEngine.Evaluate(evt, m_processTable, alerts);

    /* 4. Evaluate threshold detection rules */
    m_thresholdEngine.Evaluate(evt, m_processTable, alerts);

    /* 5. Enrich: look up parent image path */
    std::wstring parentImagePath = m_processTable.GetParentImagePath(evt);

    /* 6. Write JSON to log file */
    m_jsonWriter.WriteEvent(evt, parentImagePath);

    /* 7. Print summary to stdout for console mode */
    PrintSummary(evt);

    /* 8. Process alert events (write to log + print) */
    for (const auto& alert : alerts) {
        m_eventsProcessed++;
        std::wstring alertParent = m_processTable.GetParentImagePath(alert);
        m_jsonWriter.WriteEvent(alert, alertParent);

        std::printf("  ** ALERT: [%s] rule=%s trigger=%s pid=%lu\n",
                    SeverityName(alert.Severity),
                    alert.Payload.Alert.RuleName,
                    SourceName(alert.Payload.Alert.TriggerSource),
                    alert.ProcessCtx.ProcessId);
    }
}

/* ── Console summary ─────────────────────────────────────────────────────── */

void
EventProcessor::PrintSummary(const SENTINEL_EVENT& evt)
{
    if (evt.Source == SentinelSourceHookDll) {
        const auto& hook = evt.Payload.Hook;
        if (hook.Function == SentinelHookNtCreateNamedPipeFile) {
            /* Pipe hook: CallingModule=pipeName, Protection=isSuspicious */
            std::printf("[%llu] source=%s PIPE_CREATE pid=%lu pipe=%S%s\n",
                        m_eventsProcessed,
                        SourceName(evt.Source),
                        evt.ProcessCtx.ProcessId,
                        hook.CallingModule,
                        hook.Protection ? " [SUSPICIOUS]" : "");
        } else {
            std::printf("[%llu] source=%s func=%s pid=%lu targetPid=%lu "
                        "addr=0x%llx size=0x%llx prot=0x%lx status=0x%08lx\n",
                        m_eventsProcessed,
                        SourceName(evt.Source),
                        HookFunctionName(hook.Function),
                        evt.ProcessCtx.ProcessId,
                        hook.TargetProcessId,
                        (unsigned long long)hook.BaseAddress,
                        (unsigned long long)hook.RegionSize,
                        hook.Protection,
                        hook.ReturnStatus);
        }
    } else if (evt.Source == SentinelSourceDriverMinifilter) {
        const auto& file = evt.Payload.File;
        static const char* fileOpNames[] = {
            "CREATE", "WRITE", "RENAME", "DELETE", "SETINFO"
        };
        const char* opName = (file.Operation >= 0 && file.Operation <= 4)
            ? fileOpNames[file.Operation] : "UNKNOWN";
        std::printf("[%llu] source=%s %s pid=%lu path=%S size=%lld hash=%s%s\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    opName,
                    file.RequestingProcessId,
                    file.FilePath,
                    file.FileSize.QuadPart,
                    file.Sha256Hex[0] ? file.Sha256Hex : "(none)",
                    file.HashSkipped ? " [skipped]" : "");
    } else if (evt.Source == SentinelSourceDriverPipe) {
        const auto& pipe = evt.Payload.Pipe;
        std::printf("[%llu] source=%s PIPE_CREATE pid=%lu pipe=%S%s\n",
                    m_eventsProcessed,
                    SourceName(evt.Source),
                    pipe.CreatingProcessId,
                    pipe.PipeName,
                    pipe.IsSuspicious ? " [SUSPICIOUS]" : "");
    } else if (evt.Source == SentinelSourceDriverProcess) {
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
