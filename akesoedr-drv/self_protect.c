/*
 * akesoedr-drv/self_protect.c
 * P11-T3: Kernel callback tamper detection and ETW heartbeat monitoring.
 *
 * Strategy: "Canary counters"
 *   Each registered callback increments a volatile counter on every
 *   invocation. A system worker thread checks these counters every 10
 *   seconds. If a counter hasn't changed in 30 seconds (3 consecutive
 *   checks), the callback was likely removed by an attacker (DKOM,
 *   direct callback array manipulation, or unregister call).
 *
 *   Additionally, the agent sends periodic heartbeats via the filter
 *   port. If no heartbeat arrives for 60 seconds, we assume the agent
 *   or its ETW trace session was killed.
 *
 * All operations run at PASSIVE_LEVEL (system thread).
 */

#include <fltKernel.h>
#include "self_protect.h"
#include "comms.h"

/* ── Configuration ─────────────────────────────────────────────────────── */

#define SP_CHECK_INTERVAL_MS        10000   /* 10 seconds between checks */
#define SP_STALE_THRESHOLD          3       /* 3 checks (30s) without change */
#define SP_HEARTBEAT_TIMEOUT_MS     60000   /* 60 seconds without heartbeat */

/* ── Canary counters (lock-free, safe at any IRQL) ─────────────────────── */

static volatile LONG g_CanaryProcess    = 0;
static volatile LONG g_CanaryRegistry   = 0;
static volatile LONG g_CanaryImageLoad  = 0;
static volatile LONG g_CanaryMinifilter = 0;

/* Previous snapshot (for delta comparison) */
static LONG g_PrevProcess    = 0;
static LONG g_PrevRegistry   = 0;
static LONG g_PrevImageLoad  = 0;
static LONG g_PrevMinifilter = 0;

/* Consecutive stale counts */
static int g_StaleProcess    = 0;
static int g_StaleRegistry   = 0;
static int g_StaleImageLoad  = 0;
static int g_StaleMinifilter = 0;

/* ── Agent heartbeat tracking ──────────────────────────────────────────── */

static LARGE_INTEGER g_LastHeartbeat = {0};

/* ── Thread state ──────────────────────────────────────────────────────── */

static HANDLE   g_hThread       = NULL;
static KEVENT   g_ShutdownEvent;
static BOOLEAN  g_Initialized   = FALSE;

/* ── Tamper alert emission ─────────────────────────────────────────────── */

/*
 * Emit a tamper detection event via the filter communication port.
 * Must run at PASSIVE_LEVEL (guaranteed in system thread).
 */
static void
EmitTamperEvent(
    ULONG       tamperType,     /* AKESOEDR_TAMPER_TYPE value */
    const char *detail
)
{
    /* Build a minimal event — comms layer handles the rest */
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "AkesoEDR: TAMPER DETECTED type=%lu detail=%s\n",
        tamperType, detail ? detail : "(null)"));

    /*
     * In a full implementation, we'd build an AKESOEDR_EVENT with
     * Source = AkesoEDRSourceSelfProtect and send via AkesoEDRCommsSend().
     * For now, DbgPrint is the alert mechanism — the agent monitors
     * debug output or we can add comms integration later.
     *
     * TODO: Build AKESOEDR_EVENT with Tamper payload and send via comms.
     */
}

/* ── Canary check logic ────────────────────────────────────────────────── */

static void
CheckCanary(
    const char  *name,
    volatile LONG *counter,
    LONG          *prev,
    int           *staleCount,
    ULONG          tamperType
)
{
    LONG current = InterlockedCompareExchange(counter, 0, 0);  /* atomic read */

    if (current == *prev) {
        /* Counter didn't change — might be tampered */
        (*staleCount)++;
        if (*staleCount >= SP_STALE_THRESHOLD) {
            EmitTamperEvent(tamperType, name);
            /* Reset to avoid spamming alerts every 10s */
            *staleCount = 0;
        }
    } else {
        /* Counter changed — callback is alive */
        *staleCount = 0;
    }

    *prev = current;
}

/* ── Worker thread ─────────────────────────────────────────────────────── */

static VOID
SelfProtectWorkerThread(
    _In_ PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);
    LARGE_INTEGER timeout;

    /* Negative = relative time in 100ns units */
    timeout.QuadPart = -(LONGLONG)SP_CHECK_INTERVAL_MS * 10000LL;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Self-protect thread started (interval=%dms)\n",
        SP_CHECK_INTERVAL_MS));

    /*
     * Give callbacks time to start firing before we check.
     * Wait 30 seconds on first iteration to avoid false positives
     * during startup.
     */
    {
        LARGE_INTEGER startDelay;
        startDelay.QuadPart = -30LL * 10000000LL;  /* 30 seconds */
        KeWaitForSingleObject(&g_ShutdownEvent, Executive,
                              KernelMode, FALSE, &startDelay);
    }

    while (KeWaitForSingleObject(&g_ShutdownEvent, Executive,
                                  KernelMode, FALSE, &timeout)
           == STATUS_TIMEOUT) {

        /* Check each canary counter */
        CheckCanary("ProcessNotify",  &g_CanaryProcess,    &g_PrevProcess,
                    &g_StaleProcess,   1 /* CallbackRemoved */);
        CheckCanary("RegistryNotify", &g_CanaryRegistry,   &g_PrevRegistry,
                    &g_StaleRegistry,  1);
        CheckCanary("ImageLoadNotify",&g_CanaryImageLoad,  &g_PrevImageLoad,
                    &g_StaleImageLoad, 1);
        CheckCanary("Minifilter",     &g_CanaryMinifilter, &g_PrevMinifilter,
                    &g_StaleMinifilter,1);

        /* Check agent heartbeat */
        if (g_LastHeartbeat.QuadPart != 0) {
            LARGE_INTEGER now;
            KeQuerySystemTimePrecise(&now);
            LONGLONG elapsedMs = (now.QuadPart - g_LastHeartbeat.QuadPart) / 10000LL;
            if (elapsedMs > SP_HEARTBEAT_TIMEOUT_MS) {
                EmitTamperEvent(2 /* EtwSessionStopped */,
                                "Agent heartbeat timeout");
                /* Reset to avoid repeated alerts */
                g_LastHeartbeat.QuadPart = now.QuadPart;
            }
        }
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Self-protect thread stopped\n"));

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ── Public API ────────────────────────────────────────────────────────── */

NTSTATUS
AkesoEDRSelfProtectInit(void)
{
    NTSTATUS    status;
    HANDLE      threadHandle;

    KeInitializeEvent(&g_ShutdownEvent, NotificationEvent, FALSE);

    /* Record initial heartbeat time so we don't false-alert on startup */
    KeQuerySystemTimePrecise(&g_LastHeartbeat);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        SelfProtectWorkerThread,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "AkesoEDR: PsCreateSystemThread (self-protect) failed 0x%08X\n",
            status));
        return status;
    }

    /* Convert handle to pointer for KeWaitForSingleObject in shutdown */
    ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL,
                              KernelMode, (PVOID *)&g_hThread, NULL);
    ZwClose(threadHandle);

    g_Initialized = TRUE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Self-protect initialized\n"));

    return STATUS_SUCCESS;
}

void
AkesoEDRSelfProtectShutdown(void)
{
    if (!g_Initialized)
        return;

    /* Signal the thread to exit */
    KeSetEvent(&g_ShutdownEvent, IO_NO_INCREMENT, FALSE);

    /* Wait for thread to finish (max 5 seconds) */
    if (g_hThread) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -5LL * 10000000LL;  /* 5 seconds */
        KeWaitForSingleObject(g_hThread, Executive,
                              KernelMode, FALSE, &timeout);
        ObDereferenceObject(g_hThread);
        g_hThread = NULL;
    }

    g_Initialized = FALSE;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "AkesoEDR: Self-protect shutdown complete\n"));
}

void
AkesoEDRSelfProtectHeartbeat(void)
{
    KeQuerySystemTimePrecise(&g_LastHeartbeat);
}

/* ── Canary counter increments (called from callbacks) ─────────────────── */

void AkesoEDRCanaryProcessCallback(void)   { InterlockedIncrement(&g_CanaryProcess); }
void AkesoEDRCanaryRegistryCallback(void)  { InterlockedIncrement(&g_CanaryRegistry); }
void AkesoEDRCanaryImageLoadCallback(void) { InterlockedIncrement(&g_CanaryImageLoad); }
void AkesoEDRCanaryMinifilterCallback(void){ InterlockedIncrement(&g_CanaryMinifilter); }
