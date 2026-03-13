/*
 * common/constants.h
 * Central constants for SentinelPOC — no magic numbers in any component.
 *
 * This header is the single source of truth for device names, IOCTL codes,
 * minifilter altitude, WFP GUIDs, pool tags, and other system-level constants.
 *
 * IPC-specific constants (pipe names, buffer sizes, protocol magic) live in
 * ipc.h. Telemetry field limits (max path, max cmdline, etc.) live in
 * telemetry.h. This file covers everything else.
 *
 * Compiles in kernel-mode (C17, WDK) and user-mode (C17/C++20).
 */

#ifndef SENTINEL_CONSTANTS_H
#define SENTINEL_CONSTANTS_H

#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
    #include <guiddef.h>
    #ifdef __cplusplus
    extern "C" {
    #endif
#endif

/* ── Version ─────────────────────────────────────────────────────────────── */

#define SENTINEL_VERSION            "1.0.0"
#define SENTINEL_VERSION_MAJOR      1
#define SENTINEL_VERSION_MINOR      0
#define SENTINEL_VERSION_PATCH      0

/* ── Driver device names ─────────────────────────────────────────────────── */

/* NT device name (kernel namespace) */
#define SENTINEL_DEVICE_NAME        L"\\Device\\SentinelDrv"

/* Symbolic link (user-mode visible via \\.\SentinelDrv) */
#define SENTINEL_SYMLINK_NAME       L"\\DosDevices\\SentinelDrv"

/* User-mode device path for CreateFile */
#define SENTINEL_DEVICE_USER_PATH   L"\\\\.\\SentinelDrv"

/* ── Driver service name ─────────────────────────────────────────────────── */

#define SENTINEL_DRIVER_SERVICE     L"SentinelDrv"
#define SENTINEL_AGENT_SERVICE      L"SentinelAgent"

/* ── IOCTL codes ─────────────────────────────────────────────────────────── */

/*
 * IOCTL layout:  CTL_CODE(DeviceType, Function, Method, Access)
 *
 * DeviceType:  FILE_DEVICE_UNKNOWN (0x22)
 * Function:    0x800+ (vendor range)
 * Method:      METHOD_BUFFERED (safest for variable-size data)
 * Access:      FILE_ANY_ACCESS for read-only, FILE_READ_DATA | FILE_WRITE_DATA
 *              for commands that modify state.
 */

#define SENTINEL_IOCTL_BASE         0x800

/* CLI → Agent → Driver: query status */
#define IOCTL_SENTINEL_STATUS       CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 0,      \
                                    METHOD_BUFFERED,              \
                                    FILE_ANY_ACCESS)

/* CLI → Agent: trigger on-demand scan */
#define IOCTL_SENTINEL_SCAN         CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 1,      \
                                    METHOD_BUFFERED,              \
                                    FILE_READ_ACCESS | FILE_WRITE_ACCESS)

/* CLI → Agent: reload detection rules */
#define IOCTL_SENTINEL_RULES_RELOAD CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 2,      \
                                    METHOD_BUFFERED,              \
                                    FILE_READ_ACCESS | FILE_WRITE_ACCESS)

/* CLI → Agent: get recent alerts */
#define IOCTL_SENTINEL_ALERTS       CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 3,      \
                                    METHOD_BUFFERED,              \
                                    FILE_ANY_ACCESS)

/* CLI → Agent: get connection table */
#define IOCTL_SENTINEL_CONNECTIONS  CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 4,      \
                                    METHOD_BUFFERED,              \
                                    FILE_ANY_ACCESS)

/* CLI → Agent: get tracked processes */
#define IOCTL_SENTINEL_PROCESSES    CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 5,      \
                                    METHOD_BUFFERED,              \
                                    FILE_ANY_ACCESS)

/* CLI → Agent: get hook status */
#define IOCTL_SENTINEL_HOOKS        CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 6,      \
                                    METHOD_BUFFERED,              \
                                    FILE_ANY_ACCESS)

/* Agent → Driver: enable/disable sensors */
#define IOCTL_SENTINEL_SENSOR_CTL   CTL_CODE(FILE_DEVICE_UNKNOWN, \
                                    SENTINEL_IOCTL_BASE + 7,      \
                                    METHOD_BUFFERED,              \
                                    FILE_READ_ACCESS | FILE_WRITE_ACCESS)

/* ── Pool tags (kernel allocations) ──────────────────────────────────────── */

/*
 * Every kernel allocation is tagged for leak tracking in Driver Verifier.
 * Tags are 4-byte ASCII, stored little-endian (read backwards in poolmon).
 */

#define SENTINEL_TAG_GENERAL        'cPnS'  /* SnPc — general allocations */
#define SENTINEL_TAG_EVENT          'vEnS'  /* SnEv — event buffers */
#define SENTINEL_TAG_PROCESS        'rPnS'  /* SnPr — process table entries */
#define SENTINEL_TAG_REGISTRY       'gRnS'  /* SnRg — registry callback data */
#define SENTINEL_TAG_IMAGE          'mInS'  /* SnIm — image-load data */
#define SENTINEL_TAG_OBJECT         'bOnS'  /* SnOb — object callback data */
#define SENTINEL_TAG_FILE           'lFnS'  /* SnFl — minifilter data */
#define SENTINEL_TAG_NETWORK        'tNnS'  /* SnNt — WFP callout data */
#define SENTINEL_TAG_STRING         'tSnS'  /* SnSt — string buffers */
#define SENTINEL_TAG_HASH           'sHnS'  /* SnHs — hash computation */
#define SENTINEL_TAG_KAPC           'AnS\0' /* SnA  — KAPC injection */

/* ── Minifilter altitude ─────────────────────────────────────────────────── */

/*
 * FSFilter Anti-Virus range: 320000–329998.
 * We pick 321000 to avoid conflicts with common AV products.
 * This determines the filter's position in the I/O stack.
 */

#define SENTINEL_MINIFILTER_ALTITUDE    L"321000"

/* ── WFP sublayer and callout GUIDs ──────────────────────────────────────── */

/*
 * These GUIDs are used with FwpmSubLayerAdd / FwpsCalloutRegister / FwpmCalloutAdd.
 * Generated as fixed values so they persist across driver reloads.
 */

/* SentinelPOC WFP sublayer
 * {A1B2C3D4-E5F6-7890-ABCD-EF1234567890} */
DEFINE_GUID(SENTINEL_WFP_SUBLAYER_GUID,
    0xA1B2C3D4, 0xE5F6, 0x7890,
    0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90);

/* WFP callout: ALE Auth Connect v4 (outbound)
 * {B2C3D4E5-F6A7-8901-BCDE-F12345678901} */
DEFINE_GUID(SENTINEL_WFP_CALLOUT_CONNECT_V4,
    0xB2C3D4E5, 0xF6A7, 0x8901,
    0xBC, 0xDE, 0xF1, 0x23, 0x45, 0x67, 0x89, 0x01);

/* WFP callout: ALE Auth Recv/Accept v4 (inbound)
 * {C3D4E5F6-A7B8-9012-CDEF-123456789012} */
DEFINE_GUID(SENTINEL_WFP_CALLOUT_RECV_V4,
    0xC3D4E5F6, 0xA7B8, 0x9012,
    0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12);

/* WFP filter: outbound
 * {D4E5F6A7-B8C9-0123-DEFA-234567890123} */
DEFINE_GUID(SENTINEL_WFP_FILTER_CONNECT_V4,
    0xD4E5F6A7, 0xB8C9, 0x0123,
    0xDE, 0xFA, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23);

/* WFP filter: inbound
 * {E5F6A7B8-C9D0-1234-EFAB-345678901234} */
DEFINE_GUID(SENTINEL_WFP_FILTER_RECV_V4,
    0xE5F6A7B8, 0xC9D0, 0x1234,
    0xEF, 0xAB, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34);

/* ── Object callback altitude ────────────────────────────────────────────── */

/*
 * ObRegisterCallbacks altitude string. Must be unique among all
 * registered object callback providers on the system.
 */
#define SENTINEL_OB_ALTITUDE        L"321000"

/* ── Protected process list (object callbacks, Phase 2) ──────────────────── */

#define SENTINEL_PROTECTED_PROC_COUNT   3

#ifdef _KERNEL_MODE
/* Kernel-mode: use static array in the .c file that includes this */
#else
static const WCHAR* SENTINEL_PROTECTED_PROCESSES[] = {
    L"lsass.exe",
    L"csrss.exe",
    L"services.exe"
};
#endif

/* ── Minifilter exclusion prefixes ───────────────────────────────────────── */

/*
 * File paths starting with these prefixes are excluded from minifilter
 * monitoring to reduce noise. Configurable at runtime via sentinel.conf.
 */
#define SENTINEL_FS_EXCLUDE_COUNT       3

#ifdef _KERNEL_MODE
/* Kernel-mode: define in the .c file */
#else
static const WCHAR* SENTINEL_FS_EXCLUSIONS[] = {
    L"\\Windows\\",
    L"\\Program Files\\",
    L"\\Program Files (x86)\\"
};
#endif

/* ── Registry noise filter paths ─────────────────────────────────────────── */

#define SENTINEL_REG_EXCLUDE_COUNT      2

#ifdef _KERNEL_MODE
/* Kernel-mode: define in the .c file */
#else
static const WCHAR* SENTINEL_REG_EXCLUSIONS[] = {
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Notifications"
};
#endif

/* ── Network rate limiting ───────────────────────────────────────────────── */

#define SENTINEL_NET_MAX_EVENTS_PER_SEC     100     /* Per PID */

/* ── Scanner limits ──────────────────────────────────────────────────────── */

#define SENTINEL_SCAN_MAX_FILE_SIZE         (50 * 1024 * 1024)  /* 50 MB */
#define SENTINEL_SCAN_MAX_REGION_SIZE       (10 * 1024 * 1024)  /* 10 MB per memory region */
#define SENTINEL_SCAN_CACHE_TTL_SEC         300                 /* 5 minutes */

/* ── Log rotation ────────────────────────────────────────────────────────── */

#define SENTINEL_LOG_MAX_SIZE_BYTES         (100 * 1024 * 1024) /* 100 MB */

/* ── Hook DLL ring buffer ────────────────────────────────────────────────── */

#define SENTINEL_HOOK_RING_BUFFER_SIZE      1000    /* Max buffered events */

/* ── Suspicious named pipes (Cobalt Strike defaults, Phase 5) ────────────── */

#define SENTINEL_SUSPICIOUS_PIPE_COUNT      5

#ifndef _KERNEL_MODE
static const WCHAR* SENTINEL_SUSPICIOUS_PIPES[] = {
    L"\\MSSE-",
    L"\\msagent_",
    L"\\postex_",
    L"\\status_",
    L"\\mojo.5688.8052."
};
#endif

/* ── ETW provider GUIDs (Phase 7) ────────────────────────────────────────── */

/* Microsoft-Windows-DotNETRuntime
 * {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4} */
DEFINE_GUID(SENTINEL_ETW_DOTNET_RUNTIME,
    0xE13C0D23, 0xCCBC, 0x4E12,
    0x93, 0x1B, 0xD9, 0xCC, 0x2E, 0xEE, 0x27, 0xE4);

/* Microsoft-Windows-PowerShell
 * {A0C1853B-5C40-4B15-8766-3CF1C58F985A} */
DEFINE_GUID(SENTINEL_ETW_POWERSHELL,
    0xA0C1853B, 0x5C40, 0x4B15,
    0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A);

/* Microsoft-Windows-DNS-Client
 * {1C95126E-7EEA-49A9-A3FE-A378B03DDB4D} */
DEFINE_GUID(SENTINEL_ETW_DNS_CLIENT,
    0x1C95126E, 0x7EEA, 0x49A9,
    0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D);

/* Microsoft-Windows-Security-Kerberos
 * {98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1} */
DEFINE_GUID(SENTINEL_ETW_KERBEROS,
    0x98E6CFCB, 0xEE0A, 0x41E0,
    0xA5, 0x7B, 0x62, 0x2D, 0x4E, 0x1B, 0x30, 0xB1);

/* Microsoft-Windows-Services
 * {0063715B-EEDA-4007-9429-AD526F62696E} */
DEFINE_GUID(SENTINEL_ETW_SERVICES,
    0x0063715B, 0xEEDA, 0x4007,
    0x94, 0x29, 0xAD, 0x52, 0x6F, 0x62, 0x69, 0x6E);

/* Microsoft-Antimalware-Scan-Interface
 * {2A576B87-09A7-520E-C21A-4942F0271D67} */
DEFINE_GUID(SENTINEL_ETW_AMSI,
    0x2A576B87, 0x09A7, 0x520E,
    0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67);

/* Microsoft-Windows-RPC
 * {6AD52B32-D609-4BE9-AE07-CE8DAE937E39} */
DEFINE_GUID(SENTINEL_ETW_RPC,
    0x6AD52B32, 0xD609, 0x4BE9,
    0xAE, 0x07, 0xCE, 0x8D, 0xAE, 0x93, 0x7E, 0x39);

/* Microsoft-Windows-Kernel-Process
 * {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} */
DEFINE_GUID(SENTINEL_ETW_KERNEL_PROCESS,
    0x22FB2CD6, 0x0E7B, 0x422B,
    0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16);

/* ── Custom AMSI Provider CLSID ─────────────────────────────────────────── */

/*
 * SentinelPOC custom AMSI provider — registered via IAntimalwareProvider.
 * Windows loads this COM in-process server (sentinel-amsi.dll) into any
 * AMSI-instrumented application (PowerShell, VBScript, JScript).
 * {A3F5C8D2-7B1E-4A9F-8C6D-E5B2F1A47390}
 */
DEFINE_GUID(SENTINEL_AMSI_PROVIDER_CLSID,
    0xA3F5C8D2, 0x7B1E, 0x4A9F,
    0x8C, 0x6D, 0xE5, 0xB2, 0xF1, 0xA4, 0x73, 0x90);

/* ── Close extern "C" ────────────────────────────────────────────────────── */

#ifndef _KERNEL_MODE
    #ifdef __cplusplus
    } /* extern "C" */
    #endif
#endif

#endif /* SENTINEL_CONSTANTS_H */
