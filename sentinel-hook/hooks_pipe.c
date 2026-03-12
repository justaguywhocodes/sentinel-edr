/*
 * sentinel-hook/hooks_pipe.c
 * Detour function for NtCreateNamedPipeFile (P5-T3).
 *
 * Hooks NtCreateNamedPipeFile to detect named pipe creation.
 * The pipe name is extracted from ObjectAttributes->ObjectName and
 * checked against a list of suspicious Cobalt Strike pipe prefixes.
 *
 * Design:
 *   - Pipe name stored in CallingModule field (WCHAR[260]) — same size
 *     as SENTINEL_MAX_PIPE_NAME (256), repurposed for pipe events
 *   - Protection field repurposed as IsSuspicious flag (0 or 1)
 *   - Agent-side display logic keys on Function == NtCreateNamedPipeFile
 *     to interpret these fields correctly
 *
 * Loader-lock safety:
 *   NtCreateNamedPipeFile is NOT called by the Windows loader, so
 *   loader-lock deadlock is not a concern for this hook. However, we
 *   still follow the same reentrancy guard pattern for consistency.
 */

#include <windows.h>
#include <intrin.h>
#include "hook_engine.h"
#include "hooks_common.h"
#include "constants.h"

/* ── Ntdll types ──────────────────────────────────────────────────────────── */

typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_NT, *PUNICODE_STRING_NT;

typedef struct _OBJECT_ATTRIBUTES_NT {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING_NT ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES_NT, *POBJECT_ATTRIBUTES_NT;

typedef struct _IO_STATUS_BLOCK_NT {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK_NT, *PIO_STATUS_BLOCK_NT;

typedef NTSTATUS (NTAPI *NtCreateNamedPipeFile_t)(
    PHANDLE                 FileHandle,
    ULONG                   DesiredAccess,
    POBJECT_ATTRIBUTES_NT   ObjectAttributes,
    PIO_STATUS_BLOCK_NT     IoStatusBlock,
    ULONG                   ShareAccess,
    ULONG                   CreateDisposition,
    ULONG                   CreateOptions,
    ULONG                   NamedPipeType,
    ULONG                   ReadMode,
    ULONG                   CompletionMode,
    ULONG                   MaxInstances,
    ULONG                   InboundQuota,
    ULONG                   OutboundQuota,
    PLARGE_INTEGER          DefaultTimeout
);

/* ── Trampoline ───────────────────────────────────────────────────────────── */

static NtCreateNamedPipeFile_t Original_NtCreateNamedPipeFile = NULL;

/* ── Suspicious pipe prefix list (matches constants.h) ────────────────────── */

static const WCHAR* s_SuspiciousPrefixes[] = {
    L"\\MSSE-",
    L"\\msagent_",
    L"\\postex_",
    L"\\status_",
    L"\\mojo.5688.8052."
};

#define SUSPICIOUS_PREFIX_COUNT (sizeof(s_SuspiciousPrefixes) / sizeof(s_SuspiciousPrefixes[0]))

/*
 * Case-insensitive prefix match for wide strings.
 * Returns TRUE if 'str' starts with 'prefix'.
 */
static BOOL
WcsPrefixMatch(const WCHAR *str, USHORT strLen, const WCHAR *prefix)
{
    USHORT prefixLen = 0;
    const WCHAR *p = prefix;
    while (*p) { prefixLen++; p++; }

    if (strLen < prefixLen) {
        return FALSE;
    }

    for (USHORT i = 0; i < prefixLen; i++) {
        WCHAR a = str[i];
        WCHAR b = prefix[i];
        /* Simple ASCII case fold */
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

/*
 * Check if a pipe name matches any suspicious prefix.
 * The pipe name may be a full NT path like \Device\NamedPipe\MSSE-1234
 * or a relative name like \MSSE-1234.
 *
 * We extract the final component (after the last backslash before the
 * pipe-specific part) and check prefixes against that.
 */
static BOOL
IsSuspiciousPipe(const WCHAR *name, USHORT nameLen)
{
    if (!name || nameLen == 0) return FALSE;

    /* Characters count (nameLen is in bytes for UNICODE_STRING) */
    USHORT charLen = nameLen / sizeof(WCHAR);

    /*
     * Strategy: Check prefixes against the full name at every position
     * that starts with a backslash. This handles both:
     *   \Device\NamedPipe\MSSE-1234  (full NT path)
     *   \MSSE-1234                    (relative name)
     */
    for (USHORT i = 0; i < charLen; i++) {
        if (name[i] == L'\\') {
            USHORT remaining = charLen - i;
            for (DWORD p = 0; p < SUSPICIOUS_PREFIX_COUNT; p++) {
                if (WcsPrefixMatch(&name[i], remaining, s_SuspiciousPrefixes[p])) {
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

/*
 * Extract the pipe name from the full NT path.
 * Strips \Device\NamedPipe prefix if present, keeps the leading backslash
 * on the pipe name itself (e.g., \MSSE-1234).
 */
static void
ExtractPipeName(
    const WCHAR *fullName,
    USHORT       fullNameLen,    /* in bytes */
    WCHAR       *outBuf,
    DWORD        outBufChars)
{
    if (!fullName || fullNameLen == 0 || outBufChars == 0) {
        if (outBufChars > 0) outBuf[0] = L'\0';
        return;
    }

    USHORT charLen = fullNameLen / sizeof(WCHAR);

    /* Check for \Device\NamedPipe prefix (case-insensitive) */
    static const WCHAR prefix[] = L"\\Device\\NamedPipe";
    USHORT prefixCharLen = (sizeof(prefix) / sizeof(WCHAR)) - 1; /* 17 */

    const WCHAR *src = fullName;
    USHORT srcLen = charLen;

    if (charLen > prefixCharLen) {
        BOOL match = TRUE;
        for (USHORT i = 0; i < prefixCharLen; i++) {
            WCHAR a = fullName[i];
            WCHAR b = prefix[i];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            src = fullName + prefixCharLen;
            srcLen = charLen - prefixCharLen;
        }
    }

    /* Copy to output, respecting buffer size */
    DWORD copyChars = (srcLen < outBufChars - 1) ? srcLen : (outBufChars - 1);
    for (DWORD i = 0; i < copyChars; i++) {
        outBuf[i] = src[i];
    }
    outBuf[copyChars] = L'\0';
}

/* ── Detour: NtCreateNamedPipeFile ────────────────────────────────────────── */

static NTSTATUS NTAPI
Hooked_NtCreateNamedPipeFile(
    PHANDLE                 FileHandle,
    ULONG                   DesiredAccess,
    POBJECT_ATTRIBUTES_NT   ObjectAttributes,
    PIO_STATUS_BLOCK_NT     IoStatusBlock,
    ULONG                   ShareAccess,
    ULONG                   CreateDisposition,
    ULONG                   CreateOptions,
    ULONG                   NamedPipeType,
    ULONG                   ReadMode,
    ULONG                   CompletionMode,
    ULONG                   MaxInstances,
    ULONG                   InboundQuota,
    ULONG                   OutboundQuota,
    PLARGE_INTEGER          DefaultTimeout)
{
    /* Call original first */
    NTSTATUS status;
    __try {
        status = Original_NtCreateNamedPipeFile(
            FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            ShareAccess, CreateDisposition, CreateOptions,
            NamedPipeType, ReadMode, CompletionMode,
            MaxInstances, InboundQuota, OutboundQuota, DefaultTimeout);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (SentinelEnterHook()) {
        SENTINEL_HOOK_EVENT evt = {0};
        evt.Function        = SentinelHookNtCreateNamedPipeFile;
        evt.TargetProcessId = 0;    /* Pipe creation is always self */
        evt.BaseAddress     = 0;
        evt.RegionSize      = 0;
        evt.AllocationType  = DesiredAccess;
        evt.ReturnAddress   = (ULONG_PTR)_ReturnAddress();
        evt.ReturnStatus    = status;
        evt.StackHash       = SentinelCaptureStackHash();

        /*
         * Extract pipe name from ObjectAttributes->ObjectName.
         * Store in CallingModule field (WCHAR[260]) — repurposed for pipe hooks.
         * Protection field repurposed as IsSuspicious (0 or 1).
         */
        __try {
            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer &&
                ObjectAttributes->ObjectName->Length > 0)
            {
                PUNICODE_STRING_NT objName = ObjectAttributes->ObjectName;

                /* Store pipe name in CallingModule (same WCHAR[260] buffer) */
                ExtractPipeName(
                    objName->Buffer,
                    objName->Length,
                    evt.CallingModule,
                    SENTINEL_MAX_MODULE_NAME);

                /* Check suspicious and store in Protection field */
                evt.Protection = IsSuspiciousPipe(
                    objName->Buffer, objName->Length) ? 1 : 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* ObjectAttributes may be invalid — non-fatal */
            evt.CallingModule[0] = L'\0';
            evt.Protection = 0;
        }

        SentinelEmitHookEvent(&evt);
        SentinelLeaveHook();
    }

    return status;
}

/* ── Install pipe hooks ───────────────────────────────────────────────────── */

void
InstallPipeHooks(void)
{
    InstallHook("ntdll.dll", "NtCreateNamedPipeFile",
                (void *)Hooked_NtCreateNamedPipeFile,
                (void **)&Original_NtCreateNamedPipeFile);
}
