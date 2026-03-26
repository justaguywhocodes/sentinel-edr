/*
 * common/telemetry.h
 * Canonical telemetry event schema for AkesoEDR.
 *
 * This header defines the AKESOEDR_EVENT envelope and per-sensor payload
 * structures. It is shared across all components:
 *   - akesoedr-drv   (kernel, C17, WDK)
 *   - akesoedr-hook   (user-mode, C17)
 *   - akesoedr-agent  (user-mode, C++20)
 *   - akesoedr-cli    (user-mode, C++20)
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

#ifndef AKESOEDR_TELEMETRY_H
#define AKESOEDR_TELEMETRY_H

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

#define AKESOEDR_MAX_PATH           520
#define AKESOEDR_MAX_CMDLINE        2048
#define AKESOEDR_MAX_SID_STRING     68
#define AKESOEDR_MAX_VALUE_NAME     256
#define AKESOEDR_MAX_REG_DATA       4096
#define AKESOEDR_MAX_PIPE_NAME      256
#define AKESOEDR_MAX_HASH_HEX       65      /* SHA-256 hex + null */
#define AKESOEDR_MAX_RULE_NAME      128
#define AKESOEDR_MAX_YARA_MATCH     256
#define AKESOEDR_MAX_SCRIPT_BLOCK   8192
#define AKESOEDR_MAX_ASSEMBLY_NAME  256
#define AKESOEDR_MAX_MODULE_NAME    260

/* ── Event source enum ───────────────────────────────────────────────────── */

typedef enum _AKESOEDR_EVENT_SOURCE {
    AkesoEDRSourceDriverProcess     = 0,    /* Ch. 3: PsSetCreateProcessNotifyRoutineEx */
    AkesoEDRSourceDriverThread      = 1,    /* Ch. 3: PsSetCreateThreadNotifyRoutineEx */
    AkesoEDRSourceDriverObject      = 2,    /* Ch. 4: ObRegisterCallbacks */
    AkesoEDRSourceDriverImageLoad   = 3,    /* Ch. 5: PsSetLoadImageNotifyRoutineEx */
    AkesoEDRSourceDriverRegistry    = 4,    /* Ch. 5: CmRegisterCallbackEx */
    AkesoEDRSourceDriverMinifilter  = 5,    /* Ch. 6: FltRegisterFilter */
    AkesoEDRSourceDriverNetwork     = 6,    /* Ch. 7: WFP callout */
    AkesoEDRSourceHookDll           = 7,    /* Ch. 2: inline ntdll hooks */
    AkesoEDRSourceEtw               = 8,    /* Ch. 8: ETW consumer */
    AkesoEDRSourceAmsi              = 9,    /* Ch. 10: AMSI provider */
    AkesoEDRSourceScanner           = 10,   /* Ch. 9: file/memory scanner */
    AkesoEDRSourceRuleEngine        = 11,   /* Ch. 1: detection rule alert */
    AkesoEDRSourceSelfProtect       = 12,   /* Ch. 2-12: tamper detection */
    AkesoEDRSourceDriverPipe        = 13,   /* Ch. 6: named pipe monitoring */
    AkesoEDRSourceMax
} AKESOEDR_EVENT_SOURCE;

/* ── Severity levels ─────────────────────────────────────────────────────── */

typedef enum _AKESOEDR_SEVERITY {
    AkesoEDRSeverityInformational   = 0,
    AkesoEDRSeverityLow             = 1,
    AkesoEDRSeverityMedium          = 2,
    AkesoEDRSeverityHigh            = 3,
    AkesoEDRSeverityCritical        = 4
} AKESOEDR_SEVERITY;

/* ── Process context (attached to every event) ───────────────────────────── */

typedef struct _AKESOEDR_PROCESS_CTX {
    ULONG               ProcessId;
    ULONG               ParentProcessId;
    ULONG               ThreadId;
    ULONG               SessionId;
    LARGE_INTEGER        ProcessCreateTime;
    WCHAR               ImagePath[AKESOEDR_MAX_PATH];
    WCHAR               CommandLine[AKESOEDR_MAX_CMDLINE];
    WCHAR               UserSid[AKESOEDR_MAX_SID_STRING];
    ULONG               IntegrityLevel;     /* SECURITY_MANDATORY_*_RID */
    BOOLEAN             IsElevated;
} AKESOEDR_PROCESS_CTX;

/* ── Sensor-specific payloads ────────────────────────────────────────────── */

/*
 * Ch. 3: Process creation/termination
 */
typedef struct _AKESOEDR_PROCESS_EVENT {
    BOOLEAN             IsCreate;           /* TRUE=create, FALSE=terminate */
    ULONG               NewProcessId;
    ULONG               ParentProcessId;
    ULONG               CreatingThreadId;
    WCHAR               ImagePath[AKESOEDR_MAX_PATH];
    WCHAR               CommandLine[AKESOEDR_MAX_CMDLINE];
    WCHAR               UserSid[AKESOEDR_MAX_SID_STRING];
    ULONG               IntegrityLevel;
    BOOLEAN             IsElevated;
    ULONG               ExitStatus;         /* Valid on terminate */
} AKESOEDR_PROCESS_EVENT;

/*
 * Ch. 3: Thread creation/termination
 */
typedef struct _AKESOEDR_THREAD_EVENT {
    BOOLEAN             IsCreate;
    ULONG               ThreadId;
    ULONG               OwningProcessId;
    ULONG               CreatingProcessId;
    ULONG               CreatingThreadId;
    ULONG_PTR           StartAddress;
    BOOLEAN             IsRemote;           /* CreatingPID != OwningPID */
} AKESOEDR_THREAD_EVENT;

/*
 * Ch. 4: Object handle notifications
 */
typedef enum _AKESOEDR_OBJ_OP {
    AkesoEDRObjOpCreate     = 0,
    AkesoEDRObjOpDuplicate  = 1
} AKESOEDR_OBJ_OP;

typedef enum _AKESOEDR_OBJ_TYPE {
    AkesoEDRObjTypeProcess  = 0,
    AkesoEDRObjTypeThread   = 1
} AKESOEDR_OBJ_TYPE;

typedef struct _AKESOEDR_OBJECT_EVENT {
    AKESOEDR_OBJ_OP     Operation;
    AKESOEDR_OBJ_TYPE   ObjectType;
    ULONG               SourceProcessId;
    ULONG               SourceThreadId;
    ULONG               TargetProcessId;
    WCHAR               TargetImagePath[AKESOEDR_MAX_PATH];
    ULONG               DesiredAccess;
    ULONG               GrantedAccess;
} AKESOEDR_OBJECT_EVENT;

/*
 * Ch. 5: Image-load notifications
 */
typedef struct _AKESOEDR_IMAGELOAD_EVENT {
    ULONG               ProcessId;
    WCHAR               ImagePath[AKESOEDR_MAX_PATH];
    ULONG_PTR           ImageBase;
    SIZE_T              ImageSize;
    BOOLEAN             IsKernelImage;
    BOOLEAN             IsSigned;
    BOOLEAN             IsSignatureValid;
} AKESOEDR_IMAGELOAD_EVENT;

/*
 * Ch. 5: Registry notifications
 */
typedef enum _AKESOEDR_REG_OP {
    AkesoEDRRegOpCreateKey  = 0,
    AkesoEDRRegOpOpenKey    = 1,
    AkesoEDRRegOpSetValue   = 2,
    AkesoEDRRegOpDeleteValue= 3,
    AkesoEDRRegOpDeleteKey  = 4,
    AkesoEDRRegOpRenameKey  = 5
} AKESOEDR_REG_OP;

typedef struct _AKESOEDR_REGISTRY_EVENT {
    AKESOEDR_REG_OP     Operation;
    WCHAR               KeyPath[AKESOEDR_MAX_PATH];
    WCHAR               ValueName[AKESOEDR_MAX_VALUE_NAME];
    ULONG               DataType;           /* REG_SZ, REG_DWORD, etc. */
    ULONG               DataSize;
    UCHAR               Data[AKESOEDR_MAX_REG_DATA];
} AKESOEDR_REGISTRY_EVENT;

/*
 * Ch. 6: Filesystem minifilter events
 */
typedef enum _AKESOEDR_FILE_OP {
    AkesoEDRFileOpCreate    = 0,
    AkesoEDRFileOpWrite     = 1,
    AkesoEDRFileOpRename    = 2,
    AkesoEDRFileOpDelete    = 3,
    AkesoEDRFileOpSetInfo   = 4
} AKESOEDR_FILE_OP;

typedef struct _AKESOEDR_FILE_EVENT {
    AKESOEDR_FILE_OP    Operation;
    ULONG               RequestingProcessId;
    WCHAR               FilePath[AKESOEDR_MAX_PATH];
    WCHAR               NewFilePath[AKESOEDR_MAX_PATH]; /* For rename */
    LARGE_INTEGER        FileSize;
    CHAR                Sha256Hex[AKESOEDR_MAX_HASH_HEX];
    BOOLEAN             HashSkipped;        /* File > 50MB */
} AKESOEDR_FILE_EVENT;

/*
 * Ch. 6: Named pipe monitoring (minifilter sub-event)
 */
typedef struct _AKESOEDR_PIPE_EVENT {
    WCHAR               PipeName[AKESOEDR_MAX_PIPE_NAME];
    ULONG               CreatingProcessId;
    ULONG               AccessMode;
    BOOLEAN             IsSuspicious;       /* Matches known-bad pipe list */
} AKESOEDR_PIPE_EVENT;

/*
 * Ch. 7: Network events (WFP callout)
 */
typedef enum _AKESOEDR_NET_DIRECTION {
    AkesoEDRNetInbound  = 0,
    AkesoEDRNetOutbound = 1
} AKESOEDR_NET_DIRECTION;

typedef struct _AKESOEDR_NETWORK_EVENT {
    AKESOEDR_NET_DIRECTION Direction;
    ULONG               ProcessId;
    ULONG               Protocol;           /* IPPROTO_TCP, IPPROTO_UDP */
    ULONG               LocalAddr;          /* IPv4 in network byte order */
    USHORT              LocalPort;
    ULONG               RemoteAddr;
    USHORT              RemotePort;
} AKESOEDR_NETWORK_EVENT;

/*
 * Ch. 2: Function-hook DLL events
 */
typedef enum _AKESOEDR_HOOK_FUNCTION {
    AkesoEDRHookNtAllocateVirtualMemory     = 0,
    AkesoEDRHookNtProtectVirtualMemory      = 1,
    AkesoEDRHookNtWriteVirtualMemory        = 2,
    AkesoEDRHookNtReadVirtualMemory         = 3,
    AkesoEDRHookNtCreateThreadEx            = 4,
    AkesoEDRHookNtMapViewOfSection          = 5,
    AkesoEDRHookNtUnmapViewOfSection        = 6,
    AkesoEDRHookNtQueueApcThread            = 7,
    AkesoEDRHookNtOpenProcess               = 8,
    AkesoEDRHookNtSuspendThread             = 9,
    AkesoEDRHookNtResumeThread              = 10,
    AkesoEDRHookNtCreateSection             = 11,
    AkesoEDRHookNtCreateNamedPipeFile       = 12,
    AkesoEDRHookMax
} AKESOEDR_HOOK_FUNCTION;

typedef struct _AKESOEDR_HOOK_EVENT {
    AKESOEDR_HOOK_FUNCTION  Function;
    ULONG               TargetProcessId;    /* 0 if self */
    ULONG_PTR           BaseAddress;
    SIZE_T              RegionSize;
    ULONG               Protection;         /* PAGE_* flags */
    ULONG               AllocationType;     /* MEM_* flags */
    ULONG_PTR           ReturnAddress;
    WCHAR               CallingModule[AKESOEDR_MAX_MODULE_NAME];
    ULONG               StackHash;
    NTSTATUS            ReturnStatus;
    /*
     * P11-T1: Evasion detection flags (bitfield).
     *   Bit 0: Return address outside known modules (direct syscall)
     *   Bit 1: ntdll .text section integrity mismatch (remap)
     */
    ULONG               EvasionFlags;
} AKESOEDR_HOOK_EVENT;

#define AKESOEDR_EVASION_DIRECT_SYSCALL   0x1
#define AKESOEDR_EVASION_NTDLL_REMAP      0x2

/*
 * Ch. 8: ETW events (aggregated from multiple providers)
 */
typedef enum _AKESOEDR_ETW_PROVIDER {
    AkesoEDREtwDotNet       = 0,    /* Microsoft-Windows-DotNETRuntime */
    AkesoEDREtwPowerShell   = 1,    /* Microsoft-Windows-PowerShell */
    AkesoEDREtwDnsClient    = 2,    /* Microsoft-Windows-DNS-Client */
    AkesoEDREtwKerberos     = 3,    /* Microsoft-Windows-Security-Kerberos */
    AkesoEDREtwServices     = 4,    /* Microsoft-Windows-Services */
    AkesoEDREtwAmsi         = 5,    /* Microsoft-Antimalware-Scan-Interface */
    AkesoEDREtwRpc          = 6,    /* Microsoft-Windows-RPC */
    AkesoEDREtwKernelProc   = 7,    /* Microsoft-Windows-Kernel-Process */
    AkesoEDREtwMax
} AKESOEDR_ETW_PROVIDER;

typedef struct _AKESOEDR_ETW_EVENT {
    AKESOEDR_ETW_PROVIDER   Provider;
    USHORT              EventId;
    UCHAR               Level;
    ULONGLONG           Keyword;
    ULONG               ProcessId;
    ULONG               ThreadId;

    /* Provider-specific fields — union to save space */
    union {
        /* DotNETRuntime: assembly load */
        struct {
            WCHAR       AssemblyName[AKESOEDR_MAX_ASSEMBLY_NAME];
            WCHAR       ClassName[AKESOEDR_MAX_ASSEMBLY_NAME];
        } DotNet;

        /* PowerShell: script block */
        struct {
            ULONG       ScriptBlockId;
            ULONG       MessageNumber;
            ULONG       MessageTotal;
            WCHAR       ScriptBlock[AKESOEDR_MAX_SCRIPT_BLOCK];
        } PowerShell;

        /* DNS: query */
        struct {
            WCHAR       QueryName[AKESOEDR_MAX_PATH];
            USHORT      QueryType;
            ULONG       QueryStatus;
        } Dns;

        /* Kerberos: ticket request */
        struct {
            WCHAR       TargetName[AKESOEDR_MAX_PATH];
            ULONG       Status;
            ULONG       TicketFlags;
        } Kerberos;

        /* Services: service install */
        struct {
            WCHAR       ServiceName[AKESOEDR_MAX_PATH];
            WCHAR       ImagePath[AKESOEDR_MAX_PATH];
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
            WCHAR       ImageName[AKESOEDR_MAX_PATH];
        } KernelProcess;
    } u;
} AKESOEDR_ETW_EVENT;

/*
 * Ch. 10: AMSI scan events
 */
typedef enum _AKESOEDR_AMSI_RESULT {
    AkesoEDRAmsiClean       = 0,
    AkesoEDRAmsiSuspicious  = 1,
    AkesoEDRAmsiMalware     = 2,
    AkesoEDRAmsiBlocked     = 3
} AKESOEDR_AMSI_RESULT;

typedef struct _AKESOEDR_AMSI_EVENT {
    WCHAR               AppName[AKESOEDR_MAX_PATH];
    ULONG               ContentSize;
    AKESOEDR_AMSI_RESULT ScanResult;
    WCHAR               MatchedRule[AKESOEDR_MAX_RULE_NAME];
} AKESOEDR_AMSI_EVENT;

/*
 * Ch. 9: Scanner events (file and memory)
 */
typedef enum _AKESOEDR_SCAN_TYPE {
    AkesoEDRScanOnAccess    = 0,
    AkesoEDRScanOnDemand    = 1,
    AkesoEDRScanMemory      = 2
} AKESOEDR_SCAN_TYPE;

typedef struct _AKESOEDR_SCANNER_EVENT {
    AKESOEDR_SCAN_TYPE  ScanType;
    WCHAR               TargetPath[AKESOEDR_MAX_PATH];  /* File path or PID for memory */
    ULONG               TargetProcessId;                /* For memory scans */
    CHAR                YaraRule[AKESOEDR_MAX_YARA_MATCH];
    CHAR                Sha256Hex[AKESOEDR_MAX_HASH_HEX];
    BOOLEAN             IsMatch;
} AKESOEDR_SCANNER_EVENT;

/*
 * Rule engine alert
 */
typedef struct _AKESOEDR_ALERT_EVENT {
    CHAR                RuleName[AKESOEDR_MAX_RULE_NAME];
    AKESOEDR_SEVERITY   Severity;
    AKESOEDR_EVENT_SOURCE   TriggerSource;
    GUID                TriggerEventId;     /* Event that caused the alert */
} AKESOEDR_ALERT_EVENT;

/*
 * Self-protection / tamper detection
 */
typedef enum _AKESOEDR_TAMPER_TYPE {
    AkesoEDRTamperHookRemoved       = 0,
    AkesoEDRTamperCallbackRemoved   = 1,
    AkesoEDRTamperEtwSessionStopped = 2,
    AkesoEDRTamperAmsiPatched       = 3,
    AkesoEDRTamperDirectSyscall     = 4,
    AkesoEDRTamperNtdllRemap        = 5
} AKESOEDR_TAMPER_TYPE;

typedef struct _AKESOEDR_TAMPER_EVENT {
    AKESOEDR_TAMPER_TYPE    TamperType;
    ULONG                   ProcessId;
    WCHAR                   Detail[AKESOEDR_MAX_PATH];
} AKESOEDR_TAMPER_EVENT;

/* ── Event envelope ──────────────────────────────────────────────────────── */

typedef struct _AKESOEDR_EVENT {
    /* Header */
    GUID                    EventId;
    LARGE_INTEGER           Timestamp;
    AKESOEDR_EVENT_SOURCE   Source;
    AKESOEDR_SEVERITY       Severity;

    /* Process context of the event origin */
    AKESOEDR_PROCESS_CTX    ProcessCtx;

    /* Sensor-specific payload (tagged union) */
    union {
        AKESOEDR_PROCESS_EVENT      Process;
        AKESOEDR_THREAD_EVENT       Thread;
        AKESOEDR_OBJECT_EVENT       Object;
        AKESOEDR_IMAGELOAD_EVENT    ImageLoad;
        AKESOEDR_REGISTRY_EVENT     Registry;
        AKESOEDR_FILE_EVENT         File;
        AKESOEDR_PIPE_EVENT         Pipe;
        AKESOEDR_NETWORK_EVENT      Network;
        AKESOEDR_HOOK_EVENT         Hook;
        AKESOEDR_ETW_EVENT          Etw;
        AKESOEDR_AMSI_EVENT         Amsi;
        AKESOEDR_SCANNER_EVENT      Scanner;
        AKESOEDR_ALERT_EVENT        Alert;
        AKESOEDR_TAMPER_EVENT       Tamper;
    } Payload;

} AKESOEDR_EVENT;

/* ── Compile-time validation ─────────────────────────────────────────────── */

/*
 * Ensure the struct has no unexpected padding issues across compilers.
 * The exact size may vary with pointer width (ULONG_PTR) but should be
 * deterministic for a given architecture.
 */
#ifndef _KERNEL_MODE
    #ifdef __cplusplus
    static_assert(sizeof(AKESOEDR_EVENT) > 0, "AKESOEDR_EVENT must be non-zero size");
    static_assert(sizeof(AKESOEDR_PROCESS_CTX) > 0, "AKESOEDR_PROCESS_CTX must be non-zero size");
    #endif
#endif

/* ── Helper macros ───────────────────────────────────────────────────────── */

/*
 * Initialize an event envelope with a new GUID, current timestamp, and source.
 * Kernel callers: use KeQuerySystemTimePrecise for Timestamp.
 * User callers: use GetSystemTimePreciseAsFileTime.
 */
#ifdef _KERNEL_MODE

#define AKESOEDR_EVENT_INIT(evt, src, sev)                          \
    do {                                                            \
        RtlZeroMemory(&(evt), sizeof(AKESOEDR_EVENT));              \
        ExUuidCreate(&(evt).EventId);                               \
        KeQuerySystemTimePrecise(&(evt).Timestamp);                 \
        (evt).Source = (src);                                       \
        (evt).Severity = (sev);                                     \
    } while (0)

#else

static __inline void
AkesoEDREventInit(
    AKESOEDR_EVENT*         Event,
    AKESOEDR_EVENT_SOURCE   Source,
    AKESOEDR_SEVERITY       Severity
)
{
    ZeroMemory(Event, sizeof(AKESOEDR_EVENT));

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

#endif /* AKESOEDR_TELEMETRY_H */
