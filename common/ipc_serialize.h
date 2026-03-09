/*
 * common/ipc_serialize.h
 * Serialization helpers for SentinelPOC IPC protocol.
 *
 * These functions serialize and deserialize IPC messages to/from a byte
 * buffer suitable for transmission over a named pipe or filter port.
 *
 * Wire format:
 *   [UINT32 frame_length]   ← total bytes following this field
 *   [SENTINEL_IPC_HEADER]   ← message header (magic, version, type, etc.)
 *   [payload bytes]         ← message-type-specific payload
 *
 * All multi-byte integers are little-endian (native x64).
 *
 * Compiles in user-mode C17 and C++20.
 * Kernel-mode code uses the structs directly (no serialization needed for
 * filter port messages, which are memory-copied).
 */

#ifndef SENTINEL_IPC_SERIALIZE_H
#define SENTINEL_IPC_SERIALIZE_H

#include "ipc.h"

#ifndef _KERNEL_MODE

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef enum _SENTINEL_SERIALIZE_STATUS {
    SentinelSerializeOk             = 0,
    SentinelSerializeBufferTooSmall = 1,
    SentinelSerializeBadMagic       = 2,
    SentinelSerializeBadVersion     = 3,
    SentinelSerializeBadLength      = 4,
    SentinelSerializeBadType        = 5,
    SentinelSerializeIncomplete     = 6
} SENTINEL_SERIALIZE_STATUS;

/* ── Header helpers ──────────────────────────────────────────────────────── */

/*
 * Initialize an IPC header with magic, version, type, and payload size.
 */
static __inline void
SentinelIpcHeaderInit(
    SENTINEL_IPC_HEADER*    Header,
    SENTINEL_IPC_MSG_TYPE   Type,
    UINT32                  PayloadSize,
    UINT32                  SequenceNum
)
{
    Header->Magic       = SENTINEL_IPC_MAGIC;
    Header->Version     = SENTINEL_IPC_VERSION;
    Header->Type        = (UINT16)Type;
    Header->PayloadSize = PayloadSize;
    Header->SequenceNum = SequenceNum;
}

/*
 * Validate an IPC header. Returns SentinelSerializeOk on success.
 */
static __inline SENTINEL_SERIALIZE_STATUS
SentinelIpcHeaderValidate(
    const SENTINEL_IPC_HEADER*  Header
)
{
    if (Header->Magic != SENTINEL_IPC_MAGIC)
        return SentinelSerializeBadMagic;

    if (Header->Version != SENTINEL_IPC_VERSION)
        return SentinelSerializeBadVersion;

    if (Header->Type < SentinelMsgHandshake || Header->Type > SentinelMsgHeartbeat)
        return SentinelSerializeBadType;

    if (Header->PayloadSize > SENTINEL_IPC_MAX_PAYLOAD)
        return SentinelSerializeBadLength;

    return SentinelSerializeOk;
}

/* ── Frame write (serialize to buffer) ───────────────────────────────────── */

/*
 * Write a length-prefixed frame into a buffer.
 *
 *   Buffer layout: [UINT32 frame_length] [data bytes]
 *
 *   frame_length = DataSize (i.e., the number of bytes following the prefix).
 *
 * Parameters:
 *   Buffer      - Destination buffer.
 *   BufferSize  - Total size of Buffer in bytes.
 *   Data        - Pointer to the message struct to write.
 *   DataSize    - Size of Data in bytes.
 *   BytesWritten - On success, set to total bytes written (4 + DataSize).
 *
 * Returns SentinelSerializeOk on success, SentinelSerializeBufferTooSmall
 * if the buffer cannot hold the frame.
 */
static __inline SENTINEL_SERIALIZE_STATUS
SentinelIpcWriteFrame(
    BYTE*       Buffer,
    UINT32      BufferSize,
    const void* Data,
    UINT32      DataSize,
    UINT32*     BytesWritten
)
{
    UINT32 totalSize = sizeof(UINT32) + DataSize;

    if (BufferSize < totalSize) {
        *BytesWritten = 0;
        return SentinelSerializeBufferTooSmall;
    }

    /* Write length prefix (little-endian, native on x64) */
    *(UINT32*)Buffer = DataSize;

    /* Write payload */
    memcpy(Buffer + sizeof(UINT32), Data, DataSize);

    *BytesWritten = totalSize;
    return SentinelSerializeOk;
}

/* ── Frame read (deserialize from buffer) ────────────────────────────────── */

/*
 * Read the length prefix from a buffer and validate it.
 *
 * Parameters:
 *   Buffer       - Source buffer containing at least 4 bytes.
 *   BufferSize   - Available bytes in Buffer.
 *   FrameLength  - On success, set to the payload length (bytes after prefix).
 *
 * Returns SentinelSerializeOk if a complete length prefix is available and
 * the value is within bounds. Returns SentinelSerializeIncomplete if fewer
 * than 4 bytes are available. Returns SentinelSerializeBadLength if the
 * frame length exceeds SENTINEL_IPC_MAX_PAYLOAD.
 */
static __inline SENTINEL_SERIALIZE_STATUS
SentinelIpcReadFrameLength(
    const BYTE* Buffer,
    UINT32      BufferSize,
    UINT32*     FrameLength
)
{
    if (BufferSize < sizeof(UINT32)) {
        *FrameLength = 0;
        return SentinelSerializeIncomplete;
    }

    *FrameLength = *(const UINT32*)Buffer;

    if (*FrameLength > SENTINEL_IPC_MAX_PAYLOAD)
        return SentinelSerializeBadLength;

    return SentinelSerializeOk;
}

/*
 * Read a complete frame (length prefix + payload) from a buffer.
 *
 * Parameters:
 *   Buffer      - Source buffer.
 *   BufferSize  - Available bytes in Buffer.
 *   OutData     - Destination for the payload (caller-allocated).
 *   OutDataSize - Size of OutData buffer.
 *   BytesRead   - On success, total bytes consumed (4 + payload length).
 *
 * Returns SentinelSerializeOk on success.
 */
static __inline SENTINEL_SERIALIZE_STATUS
SentinelIpcReadFrame(
    const BYTE* Buffer,
    UINT32      BufferSize,
    void*       OutData,
    UINT32      OutDataSize,
    UINT32*     BytesRead
)
{
    UINT32 frameLength = 0;
    SENTINEL_SERIALIZE_STATUS status;

    status = SentinelIpcReadFrameLength(Buffer, BufferSize, &frameLength);
    if (status != SentinelSerializeOk) {
        *BytesRead = 0;
        return status;
    }

    /* Check that the full frame is available in the buffer */
    if (BufferSize < sizeof(UINT32) + frameLength) {
        *BytesRead = 0;
        return SentinelSerializeIncomplete;
    }

    /* Check that the output buffer is large enough */
    if (OutDataSize < frameLength) {
        *BytesRead = 0;
        return SentinelSerializeBufferTooSmall;
    }

    memcpy(OutData, Buffer + sizeof(UINT32), frameLength);
    *BytesRead = sizeof(UINT32) + frameLength;
    return SentinelSerializeOk;
}

/* ── Handshake helpers ───────────────────────────────────────────────────── */

/*
 * Build a handshake message ready for framing.
 */
static __inline void
SentinelIpcBuildHandshake(
    SENTINEL_IPC_HANDSHAKE* Msg,
    SENTINEL_CLIENT_TYPE    ClientType,
    UINT32                  ClientPid,
    UINT32                  SequenceNum
)
{
    ZeroMemory(Msg, sizeof(*Msg));
    SentinelIpcHeaderInit(
        &Msg->Header,
        SentinelMsgHandshake,
        sizeof(SENTINEL_IPC_HANDSHAKE) - sizeof(SENTINEL_IPC_HEADER),
        SequenceNum
    );
    Msg->ClientType = (UINT32)ClientType;
    Msg->ClientPid  = ClientPid;
}

/*
 * Build a handshake reply message.
 */
static __inline void
SentinelIpcBuildHandshakeReply(
    SENTINEL_IPC_HANDSHAKE_REPLY*   Msg,
    SENTINEL_HANDSHAKE_STATUS       Status,
    UINT32                          ServerPid,
    UINT32                          SequenceNum
)
{
    ZeroMemory(Msg, sizeof(*Msg));
    SentinelIpcHeaderInit(
        &Msg->Header,
        SentinelMsgHandshakeReply,
        sizeof(SENTINEL_IPC_HANDSHAKE_REPLY) - sizeof(SENTINEL_IPC_HEADER),
        SequenceNum
    );
    Msg->Status    = (UINT32)Status;
    Msg->ServerPid = ServerPid;
}

/* ── Event message helpers ───────────────────────────────────────────────── */

/*
 * Serialize a single event into a framed buffer.
 *
 * Layout: [UINT32 frame_len] [SENTINEL_IPC_EVENT_MSG] [SENTINEL_EVENT]
 *
 * Parameters:
 *   Buffer       - Destination buffer.
 *   BufferSize   - Size of Buffer.
 *   Event        - The event to serialize.
 *   SequenceNum  - Message sequence number.
 *   BytesWritten - Total bytes written to Buffer.
 */
static __inline SENTINEL_SERIALIZE_STATUS
SentinelIpcSerializeEvent(
    BYTE*                   Buffer,
    UINT32                  BufferSize,
    const SENTINEL_EVENT*   Event,
    UINT32                  SequenceNum,
    UINT32*                 BytesWritten
)
{
    SENTINEL_IPC_EVENT_MSG  msgHeader;
    UINT32                  payloadSize;
    UINT32                  totalMsgSize;
    UINT32                  totalFrameSize;

    payloadSize   = sizeof(SENTINEL_IPC_EVENT_MSG) - sizeof(SENTINEL_IPC_HEADER)
                  + sizeof(SENTINEL_EVENT);
    totalMsgSize  = sizeof(SENTINEL_IPC_EVENT_MSG) + sizeof(SENTINEL_EVENT);
    totalFrameSize = sizeof(UINT32) + totalMsgSize;

    if (BufferSize < totalFrameSize) {
        *BytesWritten = 0;
        return SentinelSerializeBufferTooSmall;
    }

    /* Build event message header */
    ZeroMemory(&msgHeader, sizeof(msgHeader));
    SentinelIpcHeaderInit(
        &msgHeader.Header,
        SentinelMsgEvent,
        payloadSize,
        SequenceNum
    );
    msgHeader.EventCount = 1;

    /* Write length prefix */
    *(UINT32*)Buffer = totalMsgSize;

    /* Write event message header */
    memcpy(Buffer + sizeof(UINT32), &msgHeader, sizeof(msgHeader));

    /* Write event payload */
    memcpy(Buffer + sizeof(UINT32) + sizeof(msgHeader), Event, sizeof(SENTINEL_EVENT));

    *BytesWritten = totalFrameSize;
    return SentinelSerializeOk;
}

/*
 * Deserialize a single event from a framed buffer.
 *
 * Parameters:
 *   Buffer      - Source buffer (must start with length prefix).
 *   BufferSize  - Available bytes.
 *   OutEvent    - Destination for the deserialized event.
 *   BytesRead   - Total bytes consumed from Buffer.
 */
static __inline SENTINEL_SERIALIZE_STATUS
SentinelIpcDeserializeEvent(
    const BYTE*         Buffer,
    UINT32              BufferSize,
    SENTINEL_EVENT*     OutEvent,
    UINT32*             BytesRead
)
{
    UINT32                  frameLength = 0;
    SENTINEL_SERIALIZE_STATUS status;
    const SENTINEL_IPC_EVENT_MSG* msgHeader;
    const BYTE*             eventData;

    /* Read and validate frame length */
    status = SentinelIpcReadFrameLength(Buffer, BufferSize, &frameLength);
    if (status != SentinelSerializeOk) {
        *BytesRead = 0;
        return status;
    }

    /* Ensure the full frame is available */
    if (BufferSize < sizeof(UINT32) + frameLength) {
        *BytesRead = 0;
        return SentinelSerializeIncomplete;
    }

    /* Validate minimum size for event message header */
    if (frameLength < sizeof(SENTINEL_IPC_EVENT_MSG)) {
        *BytesRead = 0;
        return SentinelSerializeBadLength;
    }

    /* Parse event message header */
    msgHeader = (const SENTINEL_IPC_EVENT_MSG*)(Buffer + sizeof(UINT32));

    /* Validate IPC header */
    status = SentinelIpcHeaderValidate(&msgHeader->Header);
    if (status != SentinelSerializeOk) {
        *BytesRead = 0;
        return status;
    }

    if (msgHeader->Header.Type != SentinelMsgEvent) {
        *BytesRead = 0;
        return SentinelSerializeBadType;
    }

    if (msgHeader->EventCount < 1) {
        *BytesRead = 0;
        return SentinelSerializeBadLength;
    }

    /* Ensure there's enough data for at least one event */
    if (frameLength < sizeof(SENTINEL_IPC_EVENT_MSG) + sizeof(SENTINEL_EVENT)) {
        *BytesRead = 0;
        return SentinelSerializeBadLength;
    }

    /* Copy event out */
    eventData = Buffer + sizeof(UINT32) + sizeof(SENTINEL_IPC_EVENT_MSG);
    memcpy(OutEvent, eventData, sizeof(SENTINEL_EVENT));

    *BytesRead = sizeof(UINT32) + frameLength;
    return SentinelSerializeOk;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _KERNEL_MODE */

#endif /* SENTINEL_IPC_SERIALIZE_H */
