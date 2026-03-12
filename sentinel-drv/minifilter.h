/*
 * sentinel-drv/minifilter.h
 * Filesystem minifilter I/O callbacks.
 *
 * Pre-operation callbacks filter out excluded paths and noise.
 * Post-operation callbacks emit SENTINEL_FILE_EVENT telemetry
 * for successful file create, write, rename, and delete operations.
 *
 * P5-T1: Minifilter Registration & I/O Callbacks.
 */

#ifndef SENTINEL_MINIFILTER_H
#define SENTINEL_MINIFILTER_H

#include <fltKernel.h>
#include "telemetry.h"

/* ── Shared helpers (used by file_hash.c, minifilter_pipes.c) ─────────────── */

BOOLEAN
SentinelMinifilterShouldSkipPreOp(
    _In_ PFLT_CALLBACK_DATA Data
);

void
SentinelMinifilterFillProcessCtx(
    _Out_ SENTINEL_PROCESS_CTX *Ctx,
    _In_  PFLT_CALLBACK_DATA    Data
);

void
SentinelMinifilterEmitFileEvent(
    _In_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ SENTINEL_FILE_OP      Operation
);

/* ── IRP_MJ_CREATE ──────────────────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
SentinelPreCreate(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
SentinelPostCreate(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
);

/* ── IRP_MJ_WRITE ───────────────────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
SentinelPreWrite(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
SentinelPostWrite(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
);

/* ── IRP_MJ_SET_INFORMATION (rename / delete / metadata) ────────────────── */

FLT_PREOP_CALLBACK_STATUS
SentinelPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA          Data,
    _In_    PCFLT_RELATED_OBJECTS        FltObjects,
    _Out_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
SentinelPostSetInfo(
    _Inout_  PFLT_CALLBACK_DATA         Data,
    _In_     PCFLT_RELATED_OBJECTS       FltObjects,
    _In_opt_ PVOID                       CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS    Flags
);

#endif /* SENTINEL_MINIFILTER_H */
