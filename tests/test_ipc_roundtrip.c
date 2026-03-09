/*
 * tests/test_ipc_roundtrip.c
 * Unit test: serialize a SENTINEL_EVENT, deserialize it, verify round-trip.
 *
 * Build: compiled as part of the tests/ CMake target.
 * Run:   test_ipc_roundtrip.exe — exits 0 on success, 1 on failure.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <objbase.h>    /* CoCreateGuid */

#include "telemetry.h"
#include "ipc.h"
#include "ipc_serialize.h"

/* ── Test helpers ────────────────────────────────────────────────────────── */

static int g_tests_run    = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg)                                      \
    do {                                                            \
        g_tests_run++;                                              \
        if (!(cond)) {                                              \
            printf("  FAIL: %s (line %d)\n", (msg), __LINE__);     \
            return 1;                                               \
        } else {                                                    \
            g_tests_passed++;                                       \
        }                                                           \
    } while (0)

/* ── Test: header init and validate ──────────────────────────────────────── */

static int test_header_init_validate(void)
{
    SENTINEL_IPC_HEADER hdr;
    SENTINEL_SERIALIZE_STATUS status;

    printf("[test_header_init_validate]\n");

    SentinelIpcHeaderInit(&hdr, SentinelMsgEvent, 1234, 42);

    TEST_ASSERT(hdr.Magic == SENTINEL_IPC_MAGIC,    "magic matches");
    TEST_ASSERT(hdr.Version == SENTINEL_IPC_VERSION, "version matches");
    TEST_ASSERT(hdr.Type == SentinelMsgEvent,       "type matches");
    TEST_ASSERT(hdr.PayloadSize == 1234,            "payload size matches");
    TEST_ASSERT(hdr.SequenceNum == 42,              "sequence num matches");

    status = SentinelIpcHeaderValidate(&hdr);
    TEST_ASSERT(status == SentinelSerializeOk, "header validates ok");

    /* Bad magic */
    hdr.Magic = 0xDEADBEEF;
    status = SentinelIpcHeaderValidate(&hdr);
    TEST_ASSERT(status == SentinelSerializeBadMagic, "bad magic detected");

    /* Restore and test bad version */
    hdr.Magic = SENTINEL_IPC_MAGIC;
    hdr.Version = 999;
    status = SentinelIpcHeaderValidate(&hdr);
    TEST_ASSERT(status == SentinelSerializeBadVersion, "bad version detected");

    printf("  OK\n");
    return 0;
}

/* ── Test: frame write and read ──────────────────────────────────────────── */

static int test_frame_write_read(void)
{
    BYTE buffer[256];
    BYTE payload[] = { 0x41, 0x42, 0x43, 0x44 };
    BYTE out[256];
    UINT32 bytesWritten = 0;
    UINT32 bytesRead = 0;
    SENTINEL_SERIALIZE_STATUS status;

    printf("[test_frame_write_read]\n");

    /* Write a simple frame */
    status = SentinelIpcWriteFrame(buffer, sizeof(buffer), payload, sizeof(payload), &bytesWritten);
    TEST_ASSERT(status == SentinelSerializeOk, "write frame succeeds");
    TEST_ASSERT(bytesWritten == sizeof(UINT32) + sizeof(payload), "correct bytes written");

    /* Verify length prefix */
    TEST_ASSERT(*(UINT32*)buffer == sizeof(payload), "length prefix correct");

    /* Read it back */
    status = SentinelIpcReadFrame(buffer, bytesWritten, out, sizeof(out), &bytesRead);
    TEST_ASSERT(status == SentinelSerializeOk, "read frame succeeds");
    TEST_ASSERT(bytesRead == bytesWritten, "same bytes read as written");
    TEST_ASSERT(memcmp(out, payload, sizeof(payload)) == 0, "payload round-trips");

    /* Test buffer too small */
    status = SentinelIpcWriteFrame(buffer, 2, payload, sizeof(payload), &bytesWritten);
    TEST_ASSERT(status == SentinelSerializeBufferTooSmall, "buffer too small detected");

    /* Test incomplete read */
    status = SentinelIpcReadFrame(buffer, 2, out, sizeof(out), &bytesRead);
    TEST_ASSERT(status == SentinelSerializeIncomplete, "incomplete frame detected");

    printf("  OK\n");
    return 0;
}

/* ── Test: handshake build ───────────────────────────────────────────────── */

static int test_handshake(void)
{
    SENTINEL_IPC_HANDSHAKE hs;
    SENTINEL_IPC_HANDSHAKE_REPLY reply;
    SENTINEL_SERIALIZE_STATUS status;

    printf("[test_handshake]\n");

    SentinelIpcBuildHandshake(&hs, SentinelClientHookDll, 1234, 0);

    TEST_ASSERT(hs.Header.Magic == SENTINEL_IPC_MAGIC, "handshake magic");
    TEST_ASSERT(hs.Header.Type == SentinelMsgHandshake, "handshake type");
    TEST_ASSERT(hs.ClientType == (UINT32)SentinelClientHookDll, "client type");
    TEST_ASSERT(hs.ClientPid == 1234, "client PID");

    status = SentinelIpcHeaderValidate(&hs.Header);
    TEST_ASSERT(status == SentinelSerializeOk, "handshake header valid");

    SentinelIpcBuildHandshakeReply(&reply, SentinelHandshakeOk, 5678, 0);

    TEST_ASSERT(reply.Header.Type == SentinelMsgHandshakeReply, "reply type");
    TEST_ASSERT(reply.Status == (UINT32)SentinelHandshakeOk, "reply status");
    TEST_ASSERT(reply.ServerPid == 5678, "server PID");

    printf("  OK\n");
    return 0;
}

/* ── Test: event serialization round-trip ────────────────────────────────── */

static int test_event_roundtrip(void)
{
    SENTINEL_EVENT          original;
    SENTINEL_EVENT          restored;
    BYTE                    buffer[64 * 1024];
    UINT32                  bytesWritten = 0;
    UINT32                  bytesRead = 0;
    SENTINEL_SERIALIZE_STATUS status;

    printf("[test_event_roundtrip]\n");

    /* Build a process-create event */
    SentinelEventInit(&original, SentinelSourceDriverProcess, SentinelSeverityMedium);

    original.ProcessCtx.ProcessId       = 4444;
    original.ProcessCtx.ParentProcessId = 1111;
    original.ProcessCtx.ThreadId        = 5555;
    original.ProcessCtx.SessionId       = 1;
    original.ProcessCtx.IntegrityLevel  = 0x2000;   /* SECURITY_MANDATORY_MEDIUM_RID */
    original.ProcessCtx.IsElevated      = FALSE;
    wcscpy_s(original.ProcessCtx.ImagePath, SENTINEL_MAX_PATH,
             L"C:\\Windows\\System32\\notepad.exe");
    wcscpy_s(original.ProcessCtx.CommandLine, SENTINEL_MAX_CMDLINE,
             L"notepad.exe C:\\test.txt");
    wcscpy_s(original.ProcessCtx.UserSid, SENTINEL_MAX_SID_STRING,
             L"S-1-5-21-123456789-1-1000");

    original.Payload.Process.IsCreate         = TRUE;
    original.Payload.Process.NewProcessId     = 4444;
    original.Payload.Process.ParentProcessId  = 1111;
    original.Payload.Process.CreatingThreadId = 2222;
    original.Payload.Process.IntegrityLevel   = 0x2000;
    original.Payload.Process.IsElevated       = FALSE;
    original.Payload.Process.ExitStatus       = 0;
    wcscpy_s(original.Payload.Process.ImagePath, SENTINEL_MAX_PATH,
             L"C:\\Windows\\System32\\notepad.exe");
    wcscpy_s(original.Payload.Process.CommandLine, SENTINEL_MAX_CMDLINE,
             L"notepad.exe C:\\test.txt");
    wcscpy_s(original.Payload.Process.UserSid, SENTINEL_MAX_SID_STRING,
             L"S-1-5-21-123456789-1-1000");

    /* Serialize */
    status = SentinelIpcSerializeEvent(buffer, sizeof(buffer), &original, 1, &bytesWritten);
    TEST_ASSERT(status == SentinelSerializeOk, "serialize succeeds");
    TEST_ASSERT(bytesWritten > 0, "bytes written > 0");

    printf("  Serialized event: %u bytes (frame overhead: %u bytes)\n",
           bytesWritten, (UINT32)(bytesWritten - sizeof(SENTINEL_EVENT)));

    /* Deserialize */
    ZeroMemory(&restored, sizeof(restored));
    status = SentinelIpcDeserializeEvent(buffer, bytesWritten, &restored, &bytesRead);
    TEST_ASSERT(status == SentinelSerializeOk, "deserialize succeeds");
    TEST_ASSERT(bytesRead == bytesWritten, "consumed all bytes");

    /* Verify envelope fields */
    TEST_ASSERT(IsEqualGUID(&original.EventId, &restored.EventId),
                "event ID round-trips");
    TEST_ASSERT(original.Timestamp.QuadPart == restored.Timestamp.QuadPart,
                "timestamp round-trips");
    TEST_ASSERT(original.Source == restored.Source,
                "source round-trips");
    TEST_ASSERT(original.Severity == restored.Severity,
                "severity round-trips");

    /* Verify process context */
    TEST_ASSERT(original.ProcessCtx.ProcessId == restored.ProcessCtx.ProcessId,
                "PID round-trips");
    TEST_ASSERT(original.ProcessCtx.ParentProcessId == restored.ProcessCtx.ParentProcessId,
                "PPID round-trips");
    TEST_ASSERT(original.ProcessCtx.IntegrityLevel == restored.ProcessCtx.IntegrityLevel,
                "integrity level round-trips");
    TEST_ASSERT(wcscmp(original.ProcessCtx.ImagePath,
                       restored.ProcessCtx.ImagePath) == 0,
                "image path round-trips");
    TEST_ASSERT(wcscmp(original.ProcessCtx.CommandLine,
                       restored.ProcessCtx.CommandLine) == 0,
                "command line round-trips");
    TEST_ASSERT(wcscmp(original.ProcessCtx.UserSid,
                       restored.ProcessCtx.UserSid) == 0,
                "user SID round-trips");

    /* Verify payload */
    TEST_ASSERT(original.Payload.Process.IsCreate == restored.Payload.Process.IsCreate,
                "process IsCreate round-trips");
    TEST_ASSERT(original.Payload.Process.NewProcessId == restored.Payload.Process.NewProcessId,
                "process NewProcessId round-trips");
    TEST_ASSERT(original.Payload.Process.CreatingThreadId == restored.Payload.Process.CreatingThreadId,
                "process CreatingThreadId round-trips");
    TEST_ASSERT(wcscmp(original.Payload.Process.ImagePath,
                       restored.Payload.Process.ImagePath) == 0,
                "process payload image path round-trips");

    /* Verify full binary equality */
    TEST_ASSERT(memcmp(&original, &restored, sizeof(SENTINEL_EVENT)) == 0,
                "full struct binary equality");

    printf("  OK\n");
    return 0;
}

/* ── Test: buffer too small for event ────────────────────────────────────── */

static int test_event_buffer_too_small(void)
{
    SENTINEL_EVENT event;
    BYTE tiny[64];
    UINT32 bytesWritten = 0;
    SENTINEL_SERIALIZE_STATUS status;

    printf("[test_event_buffer_too_small]\n");

    SentinelEventInit(&event, SentinelSourceDriverProcess, SentinelSeverityLow);

    status = SentinelIpcSerializeEvent(tiny, sizeof(tiny), &event, 0, &bytesWritten);
    TEST_ASSERT(status == SentinelSerializeBufferTooSmall, "tiny buffer rejected");
    TEST_ASSERT(bytesWritten == 0, "no bytes written on failure");

    printf("  OK\n");
    return 0;
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    int failed = 0;

    printf("=== SentinelPOC IPC Round-Trip Tests ===\n\n");

    failed += test_header_init_validate();
    failed += test_frame_write_read();
    failed += test_handshake();
    failed += test_event_roundtrip();
    failed += test_event_buffer_too_small();

    printf("\n=== Results: %d/%d passed ===\n", g_tests_passed, g_tests_run);

    if (failed > 0) {
        printf("FAILED\n");
        return 1;
    }

    printf("ALL PASSED\n");
    return 0;
}
