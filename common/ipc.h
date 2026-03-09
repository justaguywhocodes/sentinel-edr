/*
 * common/ipc.h
 * IPC protocol definitions for SentinelPOC.
 *
 * Two transport paths:
 *   1. Driver → Agent:  Filter communication port (FltCreateCommunicationPort)
 *   2. Hook DLL → Agent: Named pipe (\\.\pipe\SentinelTelemetry)
 *   3. CLI → Agent:      Named pipe (\\.\pipe\SentinelCommand)
 *
 * Message framing (both transports):
 *   [4-byte little-endian length] [payload]
 *
 *   The length field contains the size of the payload only (not including
 *   the 4-byte length prefix itself).
 *
 * Protocol:
 *   - Client sends SENTINEL_IPC_HANDSHAKE as the first message after connect.
 *   - Server validates magic + version, replies with SENTINEL_IPC_HANDSHAKE_REPLY.
 *   - After handshake, client sends SENTINEL_IPC_MSG containing events.
 *   - Server may send SENTINEL_IPC_MSG containing commands (CLI path).
 *   - Either side may send SENTINEL_IPC_DISCONNECT before closing.
 *
 * Compiles in kernel-mode (C17, WDK), user-mode C17, and user-mode C++20.
 */

#ifndef SENTINEL_IPC_H
#define SENTINEL_IPC_H

#ifdef _KERNEL_MODE
    #include <ntddk.h>
#else
    #include <windows.h>
    #ifdef __cplusplus
    extern "C" {
    #endif
#endif

#include "telemetry.h"

/* ── Pipe / port names ───────────────────────────────────────────────────── */

/* Named pipe for hook DLL → agent telemetry */
#define SENTINEL_PIPE_TELEMETRY     L"\\\\.\\pipe\\SentinelTelemetry"

/* Named pipe for CLI → agent commands */
#define SENTINEL_PIPE_COMMAND       L"\\\\.\\pipe\\SentinelCommand"

/* Filter communication port for driver → agent */
#define SENTINEL_FILTER_PORT_NAME   L"\\SentinelPort"

/* ── Protocol constants ──────────────────────────────────────────────────── */

#define SENTINEL_IPC_MAGIC          0x534E5443  /* 'SNTC' */
#define SENTINEL_IPC_VERSION        1

/* Maximum message payload size (64 KB — generous for a single event) */
#define SENTINEL_IPC_MAX_PAYLOAD    (64 * 1024)

/* Maximum number of events that can be batched in a single message */
#define SENTINEL_IPC_MAX_BATCH      16

/* Named pipe buffer sizes */
#define SENTINEL_PIPE_IN_BUFFER     (128 * 1024)
#define SENTINEL_PIPE_OUT_BUFFER    (128 * 1024)

/* Named pipe max instances */
#define SENTINEL_PIPE_MAX_INSTANCES 64

/* ── Message types ───────────────────────────────────────────────────────── */

typedef enum _SENTINEL_IPC_MSG_TYPE {
    SentinelMsgHandshake        = 1,
    SentinelMsgHandshakeReply   = 2,
    SentinelMsgEvent            = 3,    /* Telemetry event(s) */
    SentinelMsgCommand          = 4,    /* CLI command */
    SentinelMsgCommandReply     = 5,    /* Command response */
    SentinelMsgDisconnect       = 6,
    SentinelMsgHeartbeat        = 7
} SENTINEL_IPC_MSG_TYPE;

/* ── Message frame header ────────────────────────────────────────────────── */

/*
 * Wire format:
 *   [UINT32 TotalLength]        ← size of everything after this field
 *   [SENTINEL_IPC_HEADER]       ← message header
 *   [payload bytes]             ← type-specific payload
 *
 * TotalLength = sizeof(SENTINEL_IPC_HEADER) + payload size
 */

#pragma pack(push, 1)

typedef struct _SENTINEL_IPC_HEADER {
    UINT32                  Magic;          /* SENTINEL_IPC_MAGIC */
    UINT16                  Version;        /* SENTINEL_IPC_VERSION */
    UINT16                  Type;           /* SENTINEL_IPC_MSG_TYPE */
    UINT32                  PayloadSize;    /* Size of payload following this header */
    UINT32                  SequenceNum;    /* Monotonically increasing per connection */
} SENTINEL_IPC_HEADER;

/* ── Handshake (client → server) ─────────────────────────────────────────── */

typedef enum _SENTINEL_CLIENT_TYPE {
    SentinelClientDriver    = 1,
    SentinelClientHookDll   = 2,
    SentinelClientCli       = 3
} SENTINEL_CLIENT_TYPE;

typedef struct _SENTINEL_IPC_HANDSHAKE {
    SENTINEL_IPC_HEADER     Header;
    UINT32                  ClientType;     /* SENTINEL_CLIENT_TYPE */
    UINT32                  ClientPid;
} SENTINEL_IPC_HANDSHAKE;

/* ── Handshake reply (server → client) ───────────────────────────────────── */

typedef enum _SENTINEL_HANDSHAKE_STATUS {
    SentinelHandshakeOk         = 0,
    SentinelHandshakeBadMagic   = 1,
    SentinelHandshakeBadVersion = 2,
    SentinelHandshakeRejected   = 3
} SENTINEL_HANDSHAKE_STATUS;

typedef struct _SENTINEL_IPC_HANDSHAKE_REPLY {
    SENTINEL_IPC_HEADER     Header;
    UINT32                  Status;         /* SENTINEL_HANDSHAKE_STATUS */
    UINT32                  ServerPid;
} SENTINEL_IPC_HANDSHAKE_REPLY;

/* ── Event message (telemetry data) ──────────────────────────────────────── */

typedef struct _SENTINEL_IPC_EVENT_MSG {
    SENTINEL_IPC_HEADER     Header;
    UINT32                  EventCount;     /* Number of events in batch (1..MAX_BATCH) */
    /* Followed by EventCount x SENTINEL_EVENT structs */
} SENTINEL_IPC_EVENT_MSG;

/* ── Command message (CLI → agent) ───────────────────────────────────────── */

typedef enum _SENTINEL_CMD_TYPE {
    SentinelCmdStatus       = 1,
    SentinelCmdAlerts       = 2,
    SentinelCmdScan         = 3,
    SentinelCmdRulesReload  = 4,
    SentinelCmdConnections  = 5,
    SentinelCmdProcesses    = 6,
    SentinelCmdHooks        = 7
} SENTINEL_CMD_TYPE;

#define SENTINEL_CMD_MAX_ARG    512

typedef struct _SENTINEL_IPC_COMMAND {
    SENTINEL_IPC_HEADER     Header;
    UINT32                  CommandType;    /* SENTINEL_CMD_TYPE */
    WCHAR                   Argument[SENTINEL_CMD_MAX_ARG];
} SENTINEL_IPC_COMMAND;

/* ── Command reply (agent → CLI) ─────────────────────────────────────────── */

#define SENTINEL_CMD_MAX_REPLY  (32 * 1024)

typedef struct _SENTINEL_IPC_COMMAND_REPLY {
    SENTINEL_IPC_HEADER     Header;
    UINT32                  CommandType;    /* Echo back the command type */
    UINT32                  Status;         /* 0 = success */
    UINT32                  DataSize;       /* Size of data following this struct */
    /* Followed by DataSize bytes of response data (JSON) */
} SENTINEL_IPC_COMMAND_REPLY;

/* ── Disconnect message ──────────────────────────────────────────────────── */

typedef struct _SENTINEL_IPC_DISCONNECT {
    SENTINEL_IPC_HEADER     Header;
    UINT32                  Reason;         /* 0 = normal, 1 = error */
} SENTINEL_IPC_DISCONNECT;

/* ── Heartbeat message ───────────────────────────────────────────────────── */

typedef struct _SENTINEL_IPC_HEARTBEAT {
    SENTINEL_IPC_HEADER     Header;
    UINT64                  UptimeMs;
    UINT32                  EventsProcessed;
} SENTINEL_IPC_HEARTBEAT;

#pragma pack(pop)

/* ── Filter communication port structures (driver ↔ agent) ───────────────── */

/*
 * These map to the FltSendMessage / FilterGetMessage / FilterReplyMessage
 * protocol used between the minifilter driver and the agent service.
 *
 * The driver sends a SENTINEL_FILTER_MSG containing one event.
 * The agent replies with a SENTINEL_FILTER_REPLY containing an action.
 */

typedef struct _SENTINEL_FILTER_MSG {
    /* FilterGetMessage prepends FILTER_MESSAGE_HEADER; this is the body */
    SENTINEL_IPC_HEADER     Header;
    SENTINEL_EVENT          Event;
} SENTINEL_FILTER_MSG;

typedef enum _SENTINEL_FILTER_ACTION {
    SentinelFilterAllow     = 0,
    SentinelFilterBlock     = 1,
    SentinelFilterLog       = 2
} SENTINEL_FILTER_ACTION;

typedef struct _SENTINEL_FILTER_REPLY {
    /* FilterReplyMessage prepends FILTER_REPLY_HEADER; this is the body */
    UINT32                  Action;         /* SENTINEL_FILTER_ACTION */
} SENTINEL_FILTER_REPLY;

/* ── Close extern "C" ────────────────────────────────────────────────────── */

#ifndef _KERNEL_MODE
    #ifdef __cplusplus
    } /* extern "C" */
    #endif
#endif

#endif /* SENTINEL_IPC_H */
