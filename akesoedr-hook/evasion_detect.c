/*
 * akesoedr-hook/evasion_detect.c
 * P11-T1: Direct syscall detection + ntdll remap detection.
 *
 * Caches the base addresses and sizes of key system modules at init time,
 * then provides fast checks for hook detours to flag evasion attempts.
 *
 * Techniques detected:
 *   1. Direct syscalls (SysWhispers, HellsGate) — return address outside
 *      ntdll/kernel32/kernelbase indicates the syscall was made from
 *      shellcode or an in-memory stager.
 *   2. ntdll remapping — attacker maps a fresh copy of ntdll.dll from disk
 *      to bypass our inline hooks. Detected by CRC32 of .text section.
 */

#include <windows.h>
#include "evasion_detect.h"

/* ── Module range cache ────────────────────────────────────────────────────── */

typedef struct _MODULE_RANGE {
    ULONG_PTR   Base;
    ULONG_PTR   End;    /* Base + SizeOfImage */
} MODULE_RANGE;

static MODULE_RANGE g_Ntdll      = {0};
static MODULE_RANGE g_Kernel32   = {0};
static MODULE_RANGE g_Kernelbase = {0};
static MODULE_RANGE g_HookDll    = {0};

/* ── ntdll .text section CRC ───────────────────────────────────────────────── */

static ULONG_PTR    g_NtdllTextBase = 0;
static SIZE_T       g_NtdllTextSize = 0;
static DWORD        g_NtdllTextCrc  = 0;

/* ── CRC32 implementation (no external deps) ───────────────────────────────── */

static DWORD g_Crc32Table[256];
static BOOL  g_Crc32Initialized = FALSE;

static void
InitCrc32Table(void)
{
    for (DWORD i = 0; i < 256; i++) {
        DWORD crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        g_Crc32Table[i] = crc;
    }
    g_Crc32Initialized = TRUE;
}

static DWORD
ComputeCrc32(const BYTE *data, SIZE_T size)
{
    if (!g_Crc32Initialized)
        InitCrc32Table();

    DWORD crc = 0xFFFFFFFF;
    for (SIZE_T i = 0; i < size; i++)
        crc = g_Crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

/* ── PE header helpers ─────────────────────────────────────────────────────── */

static BOOL
GetModuleRange(const char *name, MODULE_RANGE *out)
{
    HMODULE hMod = GetModuleHandleA(name);
    if (!hMod)
        return FALSE;

    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    out->Base = (ULONG_PTR)base;
    out->End  = (ULONG_PTR)base + nt->OptionalHeader.SizeOfImage;
    return TRUE;
}

static BOOL
FindNtdllTextSection(ULONG_PTR *textBase, SIZE_T *textSize)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return FALSE;

    BYTE *base = (BYTE *)hNtdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
            sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
            sec[i].Name[4] == 't') {
            *textBase = (ULONG_PTR)base + sec[i].VirtualAddress;
            *textSize = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/* ── Public API ────────────────────────────────────────────────────────────── */

void
AkesoEDREvasionInit(void)
{
    /* Cache module address ranges */
    GetModuleRange("ntdll.dll",       &g_Ntdll);
    GetModuleRange("kernel32.dll",    &g_Kernel32);
    GetModuleRange("KERNELBASE.dll",  &g_Kernelbase);

    /* Cache our own DLL range */
    {
        HMODULE hSelf = NULL;
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)AkesoEDREvasionInit,
            &hSelf);
        if (hSelf) {
            BYTE *base = (BYTE *)hSelf;
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
            IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
            g_HookDll.Base = (ULONG_PTR)base;
            g_HookDll.End  = (ULONG_PTR)base + nt->OptionalHeader.SizeOfImage;
        }
    }

    /* Compute ntdll .text section CRC (pre-hook baseline) */
    if (FindNtdllTextSection(&g_NtdllTextBase, &g_NtdllTextSize)) {
        g_NtdllTextCrc = ComputeCrc32((const BYTE *)g_NtdllTextBase, g_NtdllTextSize);
    }
}

void
AkesoEDREvasionRecaptureBaseline(void)
{
    /*
     * Recapture CRC after hooks are installed. This is the "expected"
     * state — ntdll with our hooks in place. Any future change means
     * an attacker is unhooking or remapping.
     */
    if (g_NtdllTextBase && g_NtdllTextSize) {
        g_NtdllTextCrc = ComputeCrc32((const BYTE *)g_NtdllTextBase, g_NtdllTextSize);
    }
}

BOOL
AkesoEDRCheckReturnAddress(ULONG_PTR retAddr)
{
    if (retAddr == 0)
        return TRUE;    /* No return address — can't determine */

    /* Check against known module ranges */
    if (retAddr >= g_Ntdll.Base      && retAddr < g_Ntdll.End)      return TRUE;
    if (retAddr >= g_Kernel32.Base   && retAddr < g_Kernel32.End)   return TRUE;
    if (retAddr >= g_Kernelbase.Base && retAddr < g_Kernelbase.End) return TRUE;
    if (retAddr >= g_HookDll.Base    && retAddr < g_HookDll.End)    return TRUE;

    /*
     * Return address is outside all known modules.
     * This could be:
     *   - Direct syscall from shellcode (SysWhispers, HellsGate)
     *   - Call from JIT'd code (.NET, browser JS engine)
     *   - Call from dynamically allocated memory (injected code)
     *
     * For now, flag as suspicious. The agent's rule engine can apply
     * further context (is the process a browser? .NET runtime?).
     */
    return FALSE;
}

BOOL
AkesoEDRVerifyNtdllIntegrity(void)
{
    if (!g_NtdllTextBase || !g_NtdllTextSize)
        return TRUE;    /* Can't verify — assume OK */

    DWORD currentCrc = ComputeCrc32((const BYTE *)g_NtdllTextBase, g_NtdllTextSize);
    return (currentCrc == g_NtdllTextCrc);
}
