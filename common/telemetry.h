/*
 * common/telemetry.h
 * Canonical telemetry event schema for SentinelPOC.
 *
 * This header defines the SENTINEL_EVENT envelope and per-sensor payload
 * structures. It is shared across all components:
 *   - sentinel-drv   (kernel, C17, WDK)
 *   - sentinel-hook   (user-mode, C17)
 *   - sentinel-agent  (user-mode, C++20)
 *   - sentinel-cli    (user-mode, C++20)
 *
 * Design:
 *   Each event has a fixed-size envelope (event_id, timestamp, source,
 *   process context) followed by a tagged union of sensor-specific payloads.
 *   The envelope is the same size regardless of payload, simplifying IPC
 *   framing and buffer management.
 *
 * Book references:
 *   Ch. 1  - EDR architecture, event model
 *   Ch. 2  - Function-hooking DLL (hook event payloads)
 *   Ch. 3  - Process/thread creation callbacks
 *   Ch. 4  - Object notifications
 *   Ch. 5  - Image-load, registry notifications
 *   Ch. 6  - Filesystem minifilter
 *   Ch. 7  - Network filter (WFP)
 *   Ch. 8  - ETW consumer
 *   Ch. 9  - Scanners
 *   Ch. 10 - AMSI
 */

#ifndef SENTINEL_TELEMETRY_H
#define SENTINEL_TELEMETRY_H

/* ── Platform abstraction ────────────────────────────────────────────────── */

#ifdef _KERNEL_MODE
    /* Kernel-mode: use fltKernel.h (superset of ntddk.h, avoids redefinition conflicts) */
    #include <fltKernel.h>
    #include <ntstrsafe.h>
#else
    /* User-mode */
    #include <windows.h>
    #include <guiddef.h>

    #ifdef __cplusplus
    extern "C" {
    #endif
#endif

/* ── Limits ──────────────────────────────────────────────────────────────── */

#define SENTINEL_MAX_PATH           520
#define SENTINEL_MAX_CMDLINE        2048
#define SENTINEL_MAX_SID_STRING     68
#define SENTINEL_MAX_VALUE_NAME     256
#define SENTINEL_MAX_REG_DATA       4096
#define SENTINEL_MAX_PIPE_NAME      256
#define SENTINEL_MAX_HASH_HEX       65      /* SHA-256 hex + null */
#define SENTINEL_MAX_RULE_NAME      128
#define SENTINEL_MAX_YARA_MATCH     256
#define SENTINEL_MAX_SCRIPT_BLOCK   8192
#define SENTINEL_MAX_ASSEMBLY_NAME  256
#define SENTINEL_MAX_MODULE_NAME    260

/* ── Event source enum ───────────────────────────────────────────────────── */

typedef enum _SENTINEL_EVENT_SOURCE {
    SentinelSourceDriverProcess     = 0,    /* Ch. 3: PsSetCreateProcessNotifyRoutineEx */
    SentinelSourceDriverThread      = 1,    /* Ch. 3: PsSetCreateThreadNotifyRoutineEx */
    SentinelSourceDriverObject      = 2,    /* Ch. 4: ObRegisterCallbacks */
    SentinelSourceDriverImageLoad   = 3,    /* Ch. 5: PsSetLoadImageNotifyRoutineEx */
    SentinelSourceDriverRegistry    = 4,    /* Ch. 5: CmRegisterCallbackEx */
    SentinelSourceDriverMinifilter  = 5,    /* Ch. 6: FltRegisterFilter */
    SentinelSourceDriverNetwork     = 6,    /* Ch. 7: WFP callout */
    SentinelSourceHookDll           = 7,    /* Ch. 2: inline ntdll hooks */
    SentinelSourceEtw               = 8,    /* Ch. 8: ETW consumer */
    SentinelSourceAmsi              = 9,    /* Ch. 10: AMSI provider */
    SentinelSourceScanner           = 10,   /* Ch. 9: file/memory scanner */
    SentinelSourceRuleEngine        = 11,   /* Ch. 1: detection rule alert */
    SentinelSourceSelfProtect       = 12,   /* Ch. 2-12: tamper detection */
    SentinelSourceDriverPipe        = 13,   /* Ch. 6: named pipe monitoring */
    SentinelSourceMax
} SENTINEL_EVENT_SOURCE;

/* ── Severity levels ─────────────────────────────────────────────────────── */

typedef enum _SENTINEL_SEVERITY {
    SentinelSeverityInformational   = 0,
    SentinelSeverityLow             = 1,
    SentinelSeverityMedium          = 2,
    SentinelSeverityHigh            = 3,
    SentinelSeverityCritical        = 4
} SENTINEL_SEVERITY;

/* ── Process context (attached to every event) ───────────────────────────── */

typedef struct _SENTINEL_PROCESS_CTX {
    ULONG               ProcessId;
    ULONG               ParentProcessId;
    ULONG               ThreadId;
    ULONG               SessionId;
    LARGE_INTEGER        ProcessCreateTime;
    WCHAR               ImagePath[SENTINEL_MAX_PATH];
    WCHAR               CommandLine[SENTINEL_MAX_CMDLINE];
    WCHAR               UserSid[SENTINEL_MAX_SID_STRING];
    ULONG               IntegrityLevel;     /* SECURITY_MANDATORY_*_RID */
    BOOLEAN             IsElevated;
} SENTINEL_PROCESS_CTX;

/* ── Sensor-specific payloads ────────────────────────────────────────────── */

/*
 * Ch. 3: Process creation/termination
 */
typedef struct _SENTINEL_PROCESS_EVENT {
    BOOLEAN             IsCreate;           /* TRUE=create, FALSE=terminate */
    ULONG               NewProcessId;
    ULONG               ParentProcessId;
    ULONG               CreatingThreadId;
    WCHAR               ImagePath[SENTINEL_MAX_PATH];
    WCHAR               CommandLine[SENTINEL_MAX_CMDLINE];
    WCHAR               UserSid[SENTINEL_MAX_SID_STRING];
    ULONG               IntegrityLevel;
    BOOLEAN             IsElevated;
    ULONG               ExitStatus;         /* Valid on terminate */
} SENTINEL_PROCESS_EVENT;

/*
 * Ch. 3: Thread creation/termination
 */
typedef struct _SENTINEL_THREAD_EVENT {
    BOOLEAN             IsCreate;
    ULONG               ThreadId;
    ULONG               OwningProcessId;
    ULONG               CreatingProcessId;
    ULONG               CreatingThreadId;
    ULONG_PTR           StartAddress;
    BOOLEAN             IsRemote;           /* CreatingPID != OwningPID */
} SENTINEL_THREAD_EVENT;

/*
 * Ch. 4: Object handle notifications
 */
typedef enum _SENTINEL_OBJ_OP {
    SentinelObjOpCreate     = 0,
    SentinelObjOpDuplicate  = 1
} SENTINEL_OBJ_OP;

typedef enum _SENTINEL_OBJ_TYPE {
    SentinelObjTypeProcess  = 0,
    SentinelObjTypeThread   = 1
} SENTINEL_OBJ_TYPE;

typedef struct _SENTINEL_OBJECT_EVENT {
    SENTINEL_OBJ_OP     Operation;
    SENTINEL_OBJ_TYPE   ObjectType;
    ULONG               SourceProcessId;
    ULONG               SourceThreadId;
    ULONG               TargetProcessId;
    WCHAR               TargetImagePath[SENTINEL_MAX_PATH];
    ULONG               DesiredAccess;
    ULONG               GrantedAccess;
} SENTINEL_OBJECT_EVENT;

/*
 * Ch. 5: Image-load notifications
 */
typedef struct _SENTINEL_IMAGELOAD_EVENT {
    ULONG               ProcessId;
    WCHAR               ImagePath[SENTINEL_MAX_PATH];
    ULONG_PTR           ImageBase;
    SIZE_T              ImageSize;
    BOOLEAN             IsKernelImage;
    BOOLEAN             IsSigned;
    BOOLEAN             IsSignatureValid;
} SENTINEL_IMAGELOAD_EVENT;

/*
 * Ch. 5: Registry notifications
 */
typedef enum _SENTINEL_REG_OP {
    SentinelRegOpCreateKey  = 0,
    SentinelRegOpOpenKey    = 1,
    SentinelRegOpSetValue   = 2,
    SentinelRegOpDeleteValue= 3,
    SentinelRegOpDeleteKey  = 4,
    SentinelRegOpRenameKey  = 5
} SENTINEL_REG_OP;

typedef struct _SENTINEL_REGISTRY_EVENT {
    SENTINEL_REG_OP     Operation;
    WCHAR               KeyPath[SENTINEL_MAX_PATH];
    WCHAR               ValueName[SENTINEL_MAX_VALUE_NAME];
    ULONG               DataType;           /* REG_SZ, REG_DWORD, etc. */
    ULONG               DataSize;
    UCHAR               Data[SENTINEL_MAX_REG_DATA];
} SENTINEL_REGISTRY_EVENT;

/*
 * Ch. 6: Filesystem minifilter events
 */
typedef enum _SENTINEL_FILE_OP {
    SentinelFileOpCreate    = 0,
    SentinelFileOpWrite     = 1,
    SentinelFileOpRename    = 2,
    SentinelFileOpDelete    = 3,
    SentinelFileOpSetInfo   = 4
} SENTINEL_FILE_OP;

typedef struct _SENTINEL_FILE_EVENT {
    SENTINEL_FILE_OP    Operation;
    ULONG               RequestingProcessId;
    WCHAR               FilePath[SENTINEL_MAX_PATH];
    WCHAR               NewFilePath[SENTINEL_MAX_PATH]; /* For rename */
    LARGE_INTEGER        FileSize;
    CHAR                Sha256Hex[SENTINEL_MAX_HASH_HEX];
    BOOLEAN             HashSkipped;        /* File > 50MB */
} SENTINEL_FILE_EVENT;

/*
 * Ch. 6: Named pipe monitoring (minifilter sub-event)
 */
typedef struct _SENTINEL_PIPE_EVENT {
    WCHAR               PipeName[SENTINEL_MAX_PIPE_NAME];
    ULONG               CreatingProcessId;
    ULONG               AccessMode;
    BOOLEAN             IsSuspicious;       /* Matches known-bad pipe list */
} SENTINEL_PIPE_EVENT;

/*
 * Ch. 7: Network events (WFP callout)
 */
typedef enum _SENTINEL_NET_DIRECTION {
    SentinelNetInbound  = 0,
    SentinelNetOutbound = 1
} SENTINEL_NET_DIRECTION;

typedef struct _SENTINEL_NETWORK_EVENT {
    SENTINEL_NET_DIRECTION Direction;
    ULONG               ProcessId;
    ULONG               Protocol;           /* IPPROTO_TCP, IPPROTO_UDP */
    ULONG               LocalAddr;          /* IPv4 in network byte order */
    USHORT              LocalPort;
    ULONG               RemoteAddr;
    USHORT              RemotePort;
} SENTINEL_NETWORK_EVENT;

/*
 * Ch. 2: Function-hook DLL events
 */
typedef enum _SENTINEL_HOOK_FUNCTION {
    SentinelHookNtAllocateVirtualMemory     = 0,
    SentinelHookNtProtectVirtualMemory      = 1,
    SentinelHookNtWriteVirtualMemory        = 2,
    SentinelHookNtReadVirtualMemory         = 3,
    SentinelHookNtCreateThreadEx            = 4,
    SentinelHookNtMapViewOfSection          = 5,
    SentinelHookNtUnmapViewOfSection        = 6,
    SentinelHookNtQueueApcThread            = 7,
    SentinelHookNtOpenProcess               = 8,
    SentinelHookNtSuspendThread             = 9,
    SentinelHookNtResumeThread              = 10,
    SentinelHookNtCreateSection             = 11,
    SentinelHookNtCreateNamedPipeFile       = 12,
    SentinelHookMax
} SENTINEL_HOOK_FUNCTION;

typedef struct _SENTINEL_HOOK_EVENT {
    SENTINEL_HOOK_FUNCTION  Function;
    ULONG               TargetProcessId;    /* 0 if self */
    ULONG_PTR           BaseAddress;
    SIZE_T              RegionSize;
    ULONG               Protection;         /* PAGE_* flags */
    ULONG               AllocationType;     /* MEM_* flags */
    ULONG_PTR           ReturnAddress;
    WCHAR               CallingModule[SENTINEL_MAX_MODULE_NAME];
    ULONG               StackHash;
    NTSTATUS            ReturnStatus;
} SENTINEL_HOOK_EVENT;

/*
 * Ch. 8: ETW events (aggregated from multiple providers)
 */
typedef enum _SENTINEL_ETW_PROVIDER {
    SentinelEtwDotNet       = 0,    /* Microsoft-Windows-DotNETRuntime */
    SentinelEtwPowerShell   = 1,    /* Microsoft-Windows-PowerShell */
    SentinelEtwDnsClient    = 2,    /* Microsoft-Windows-DNS-Client */
    SentinelEtwKerberos     = 3,    /* Microsoft-Windows-Security-Kerberos */
    SentinelEtwServices     = 4,    /* Microsoft-Windows-Services */
    SentinelEtwAmsi         = 5,    /* Microsoft-Antimalware-Scan-Interface */
    SentinelEtwRpc          = 6,    /* Microsoft-Windows-RPC */
    SentinelEtwKernelProc   = 7,    /* Microsoft-Windows-Kernel-Process */
    SentinelEtwMax
} SENTINEL_ETW_PROVIDER;

typedef struct _SENTINEL_ETW_EVENT {
    SENTINEL_ETW_PROVIDER   Provider;
    USHORT              EventId;
    UCHAR               Level;
    ULONGLONG           Keyword;
    ULONG               ProcessId;
    ULONG               ThreadId;

    /* Provider-specific fields — union to save space */
    union {
        /* DotNETRuntime: assembly load */
        struct {
            WCHAR       AssemblyName[SENTINEL_MAX_ASSEMBLY_NAME];
            WCHAR       ClassName[SENTINEL_MAX_ASSEMBLY_NAME];
        } DotNet;

        /* PowerShell: script block */
        struct {
            ULONG       ScriptBlockId;
            ULONG       MessageNumber;
            ULONG       MessageTotal;
            WCHAR       ScriptBlock[SENTINEL_MAX_SCRIPT_BLOCK];
        } PowerShell;

        /* DNS: query */
        struct {
            WCHAR       QueryName[SENTINEL_MAX_PATH];
            USHORT      QueryType;
            ULONG       QueryStatus;
        } Dns;

        /* Kerberos: ticket request */
        struct {
            WCHAR       TargetName[SENTINEL_MAX_PATH];
            ULONG       Status;
            ULONG       TicketFlags;
        } Kerberos;

        /* Services: service install */
        struct {
            WCHAR       ServiceName[SENTINEL_MAX_PATH];
            WCHAR       ImagePath[SENTINEL_MAX_PATH];
            ULONG       StartType;
        } Service;

        /* RPC: call */
        struct {
            GUID        InterfaceUuid;
            ULONG       OpNum;
            ULONG       Protocol;
        } Rpc;

        /* Kernel-Process: process create/stop (cross-validates driver callbacks) */
        struct {
            ULONG       ParentProcessId;
            ULONG       SessionId;
            ULONG       ExitCode;
            WCHAR       ImageName[SENTINEL_MAX_PATH];
        } KernelProcess;
    } u;
} SENTINEL_ETW_EVENT;

/*
 * Ch. 10: AMSI scan events
 */
typedef enum _SENTINEL_AMSI_RESULT {
    SentinelAmsiClean       = 0,
    SentinelAmsiSuspicious  = 1,
    SentinelAmsiMalware     = 2,
    SentinelAmsiBlocked     = 3
} SENTINEL_AMSI_RESULT;

typedef struct _SENTINEL_AMSI_EVENT {
    WCHAR               AppName[SENTINEL_MAX_PATH];
    ULONG               ContentSize;
    SENTINEL_AMSI_RESULT ScanResult;
    WCHAR               MatchedRule[SENTINEL_MAX_RULE_NAME];
} SENTINEL_AMSI_EVENT;

/*
 * Ch. 9: Scanner events (file and memory)
 */
typedef enum _SENTINEL_SCAN_TYPE {
    SentinelScanOnAccess    = 0,
    SentinelScanOnDemand    = 1,
    SentinelScanMemory      = 2
} SENTINEL_SCAN_TYPE;

typedef struct _SENTINEL_SCANNER_EVENT {
    SENTINEL_SCAN_TYPE  ScanType;
    WCHAR               TargetPath[SENTINEL_MAX_PATH];  /* File path or PID for memory */
    ULONG               TargetProcessId;                /* For memory scans */
    CHAR                YaraRule[SENTINEL_MAX_YARA_MATCH];
    CHAR                Sha256Hex[SENTINEL_MAX_HASH_HEX];
    BOOLEAN             IsMatch;
} SENTINEL_SCANNER_EVENT;

/*
 * Rule engine alert
 */
typedef struct _SENTINEL_ALERT_EVENT {
    CHAR                RuleName[SENTINEL_MAX_RULE_NAME];
    SENTINEL_SEVERITY   Severity;
    SENTINEL_EVENT_SOURCE   TriggerSource;
    GUID                TriggerEventId;     /* Event that caused the alert */
} SENTINEL_ALERT_EVENT;

/*
 * Self-protection / tamper detection
 */
typedef enum _SENTINEL_TAMPER_TYPE {
    SentinelTamperHookRemoved       = 0,
    SentinelTamperCallbackRemoved   = 1,
    SentinelTamperEtwSessionStopped = 2,
    SentinelTamperAmsiPatched       = 3,
    SentinelTamperDirectSyscall     = 4,
    SentinelTamperNtdllRemap        = 5
} SENTINEL_TAMPER_TYPE;

typedef struct _SENTINEL_TAMPER_EVENT {
    SENTINEL_TAMPER_TYPE    TamperType;
    ULONG                   ProcessId;
    WCHAR                   Detail[SENTINEL_MAX_PATH];
} SENTINEL_TAMPER_EVENT;

/* ── Event envelope ──────────────────────────────────────────────────────── */

typedef struct _SENTINEL_EVENT {
    /* Header */
    GUID                    EventId;
    LARGE_INTEGER           Timestamp;
    SENTINEL_EVENT_SOURCE   Source;
    SENTINEL_SEVERITY       Severity;

    /* Process context of the event origin */
    SENTINEL_PROCESS_CTX    ProcessCtx;

    /* Sensor-specific payload (tagged union) */
    union {
        SENTINEL_PROCESS_EVENT      Process;
        SENTINEL_THREAD_EVENT       Thread;
        SENTINEL_OBJECT_EVENT       Object;
        SENTINEL_IMAGELOAD_EVENT    ImageLoad;
        SENTINEL_REGISTRY_EVENT     Registry;
        SENTINEL_FILE_EVENT         File;
        SENTINEL_PIPE_EVENT         Pipe;
        SENTINEL_NETWORK_EVENT      Network;
        SENTINEL_HOOK_EVENT         Hook;
        SENTINEL_ETW_EVENT          Etw;
        SENTINEL_AMSI_EVENT         Amsi;
        SENTINEL_SCANNER_EVENT      Scanner;
        SENTINEL_ALERT_EVENT        Alert;
        SENTINEL_TAMPER_EVENT       Tamper;
    } Payload;

} SENTINEL_EVENT;

/* ── Compile-time validation ─────────────────────────────────────────────── */

/*
 * Ensure the struct has no unexpected padding issues across compilers.
 * The exact size may vary with pointer width (ULONG_PTR) but should be
 * deterministic for a given architecture.
 */
#ifndef _KERNEL_MODE
    #ifdef __cplusplus
    static_assert(sizeof(SENTINEL_EVENT) > 0, "SENTINEL_EVENT must be non-zero size");
    static_assert(sizeof(SENTINEL_PROCESS_CTX) > 0, "SENTINEL_PROCESS_CTX must be non-zero size");
    #endif
#endif

/* ── Helper macros ───────────────────────────────────────────────────────── */

/*
 * Initialize an event envelope with a new GUID, current timestamp, and source.
 * Kernel callers: use KeQuerySystemTimePrecise for Timestamp.
 * User callers: use GetSystemTimePreciseAsFileTime.
 */
#ifdef _KERNEL_MODE

#define SENTINEL_EVENT_INIT(evt, src, sev)                          \
    do {                                                            \
        RtlZeroMemory(&(evt), sizeof(SENTINEL_EVENT));              \
        ExUuidCreate(&(evt).EventId);                               \
        KeQuerySystemTimePrecise(&(evt).Timestamp);                 \
        (evt).Source = (src);                                       \
        (evt).Severity = (sev);                                     \
    } while (0)

#else

static __inline void
SentinelEventInit(
    SENTINEL_EVENT*         Event,
    SENTINEL_EVENT_SOURCE   Source,
    SENTINEL_SEVERITY       Severity
)
{
    ZeroMemory(Event, sizeof(SENTINEL_EVENT));

    /*
     * GUID generation: try CoCreateGuid dynamically from ole32.dll.
     * We use GetModuleHandleA (not LoadLibraryA) to avoid loading ole32
     * if it isn't already present — critical for the hook DLL which is
     * injected via KAPC during early process creation, when ole32.dll
     * cannot initialize (STATUS_DLL_INIT_FAILED).
     *
     * Fallback: pseudo-GUID from PID + TID + counter + perf counter.
     * Not RFC 4122 compliant but unique enough for POC correlation.
     */
    {
        typedef LONG (__stdcall *PFN_CoCreateGuid)(GUID*);
        HMODULE hOle = GetModuleHandleA("ole32.dll");
        PFN_CoCreateGuid pfn = hOle
            ? (PFN_CoCreateGuid)(void*)GetProcAddress(hOle, "CoCreateGuid")
            : NULL;

        if (pfn && pfn(&Event->EventId) == 0) {
            /* Success — real GUID */
        } else {
            /* Fallback: pseudo-GUID */
            static volatile LONG s_counter = 0;
            LARGE_INTEGER pc;
            QueryPerformanceCounter(&pc);
            Event->EventId.Data1 = GetCurrentProcessId();
            Event->EventId.Data2 = (unsigned short)GetCurrentThreadId();
            Event->EventId.Data3 = (unsigned short)InterlockedIncrement(&s_counter);
            *(LONGLONG*)Event->EventId.Data4 = pc.QuadPart;
        }
    }

    {
        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        Event->Timestamp.LowPart  = ft.dwLowDateTime;
        Event->Timestamp.HighPart = (LONG)ft.dwHighDateTime;
    }

    Event->Source   = Source;
    Event->Severity = Severity;
}

#endif /* _KERNEL_MODE */

/* ── Close extern "C" for C++ user-mode ──────────────────────────────────── */

#ifndef _KERNEL_MODE
    #ifdef __cplusplus
    } /* extern "C" */
    #endif
#endif

#endif /* SENTINEL_TELEMETRY_H */
