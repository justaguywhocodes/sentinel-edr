/*
 * akesoedr-hook/hook_engine.c
 * x64 inline hook engine (Ch. 2 — custom mini-Detours).
 *
 * Hook mechanism:
 *   1. Resolve target function via GetModuleHandleA + GetProcAddress
 *   2. Use a minimal x64 length disassembler to find instruction boundary >= 12 bytes
 *   3. Allocate executable trampoline, copy stolen bytes, append JMP back
 *   4. Overwrite target with: mov rax, <detour>; jmp rax (12 bytes)
 *   5. Flush instruction cache
 *
 * Unhook restores original bytes, frees trampoline.
 *
 * x64 absolute JMP (12 bytes):
 *   48 B8 <8-byte address>   ; mov rax, imm64
 *   FF E0                    ; jmp rax
 */

#include <windows.h>
#include <stdio.h>
#include "hook_engine.h"

/* ── Diagnostic logging helper ────────────────────────────────────────── */

/*
 * LOADER-LOCK SAFETY: Uses _snprintf_s (CRT, no locks) instead of
 * wsprintfA (user32.dll — creates a static import dependency that
 * causes STATUS_DLL_INIT_FAILED during early KAPC injection because
 * user32.dll cannot initialize before the process connects to csrss).
 */
#define DIAG_LOG(fmt, ...) do {                                             \
    char _dbuf[300];                                                        \
    _snprintf_s(_dbuf, sizeof(_dbuf), _TRUNCATE, fmt, __VA_ARGS__);         \
    HANDLE _hd = CreateFileA("C:\\AkesoEDR\\hook_diag.log",              \
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,              \
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);                   \
    if (_hd != INVALID_HANDLE_VALUE) {                                      \
        DWORD _w; WriteFile(_hd, _dbuf, (DWORD)lstrlenA(_dbuf), &_w, NULL);\
        CloseHandle(_hd);                                                   \
    }                                                                       \
} while(0)

/* ── Constants ─────────────────────────────────────────────────────────── */

#define MAX_HOOKS           16
#define TRAMPOLINE_SIZE     64      /* Stolen bytes + JMP back */
#define JMP_ABS_SIZE        12      /* mov rax, imm64 (10) + jmp rax (2) */
#define MAX_STOLEN_BYTES    32      /* Max bytes to analyze for boundary */

/* ── Hook entry ────────────────────────────────────────────────────────── */

typedef struct _HOOK_ENTRY {
    BOOL    Active;
    void   *TargetFunc;             /* Original function address */
    void   *DetourFunc;             /* Our replacement */
    void   *Trampoline;             /* VirtualAlloc'd executable page */
    BYTE    OriginalBytes[MAX_STOLEN_BYTES];
    DWORD   StolenSize;             /* Bytes patched (>= JMP_ABS_SIZE) */
    char    ModuleName[64];
    char    FunctionName[128];
} HOOK_ENTRY;

/* ── State ─────────────────────────────────────────────────────────────── */

static HOOK_ENTRY   g_Hooks[MAX_HOOKS];
static BOOL         g_Initialized = FALSE;

/*
 * Pre-allocated trampoline pool.
 * All trampoline memory is allocated in HookEngineInit() BEFORE any hooks
 * are installed. This avoids calling VirtualAlloc after NtAllocateVirtualMemory
 * is hooked — which fails under loader lock (ERROR_INVALID_HANDLE).
 */
static BYTE        *g_TrampolinePool = NULL;

/*
 * g_NtdllUnprotected — set once in HookEngineInit after we make all ntdll
 * code pages PAGE_EXECUTE_READWRITE.  InstallHook / RemoveHook skip
 * VirtualProtect entirely — the pages are already writable.
 */
static BOOL g_NtdllUnprotected = FALSE;

/* ── Forward declarations ──────────────────────────────────────────────── */

static DWORD AkesoEDRGetInstructionLength(const BYTE *code);
static void  WriteAbsoluteJmp(BYTE *dest, void *target);
static HOOK_ENTRY *FindFreeSlot(void);
static HOOK_ENTRY *FindHookByName(const char *moduleName, const char *funcName);

/* ── x64 Minimal Length Disassembler ───────────────────────────────────── */

/*
 * Decode one x64 instruction and return its length in bytes.
 * Returns 0 if the instruction cannot be decoded (fail-safe).
 *
 * This handles the common prologues found in ntdll/kernel32 exports:
 *   push rbx / push rdi / push r12-r15
 *   sub rsp, imm8/imm32
 *   mov [rsp+N], reg
 *   mov reg, reg
 *   lea reg, [rip+disp32]
 *   xor reg, reg
 *   test reg, reg
 *   cmp reg, imm
 *   nop / multi-byte nop
 *   jmp/jcc rel8/rel32
 */
static DWORD
AkesoEDRGetInstructionLength(const BYTE *code)
{
    const BYTE *p = code;
    BOOL hasRex = FALSE;
    BOOL has66  = FALSE;
    BOOL has67  = FALSE;
    BOOL hasF0F2F3 = FALSE;
    BYTE rex = 0;

    /* ── Prefixes ─────────────────────────────────────────────────────── */

    for (;;) {
        BYTE b = *p;

        /* REX prefix: 0x40-0x4F */
        if (b >= 0x40 && b <= 0x4F) {
            hasRex = TRUE;
            rex = b;
            p++;
            continue;
        }

        /* Operand size override */
        if (b == 0x66) { has66 = TRUE; p++; continue; }

        /* Address size override */
        if (b == 0x67) { has67 = TRUE; p++; continue; }

        /* LOCK / REPNE / REP */
        if (b == 0xF0 || b == 0xF2 || b == 0xF3) {
            hasF0F2F3 = TRUE;
            p++;
            continue;
        }

        /* Segment overrides (rare in x64 user mode) */
        if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x64 || b == 0x65) {
            p++;
            continue;
        }

        break;
    }

    BYTE opcode = *p++;

    /* ── Two-byte opcode (0x0F prefix) ────────────────────────────────── */

    if (opcode == 0x0F) {
        BYTE op2 = *p++;

        /* 0F 1F /0 — multi-byte NOP (has ModR/M) */
        if (op2 == 0x1F) {
            goto decode_modrm;
        }

        /* 0F 80-8F — Jcc rel32 */
        if (op2 >= 0x80 && op2 <= 0x8F) {
            return (DWORD)(p - code) + 4;
        }

        /* 0F B6/B7 — MOVZX r, r/m8 / r/m16 (ModR/M) */
        /* 0F BE/BF — MOVSX */
        /* 0F 40-4F — CMOVcc */
        if ((op2 >= 0x40 && op2 <= 0x4F) ||
            op2 == 0xB6 || op2 == 0xB7 ||
            op2 == 0xBE || op2 == 0xBF ||
            op2 == 0xAF ||   /* IMUL r, r/m */
            op2 == 0xBA) {   /* BT/BTS/BTR/BTC r/m, imm8 */
            goto decode_modrm;
        }

        /* 0F 05 — SYSCALL (2 bytes total) */
        if (op2 == 0x05) {
            return (DWORD)(p - code);
        }

        return 0; /* Unknown two-byte opcode */
    }

    /* ── One-byte opcodes ─────────────────────────────────────────────── */

    /* NOP */
    if (opcode == 0x90) {
        return (DWORD)(p - code);
    }

    /* INT3 */
    if (opcode == 0xCC) {
        return (DWORD)(p - code);
    }

    /* RET (near) */
    if (opcode == 0xC3) {
        return (DWORD)(p - code);
    }

    /* RET imm16 */
    if (opcode == 0xC2) {
        return (DWORD)(p - code) + 2;
    }

    /* PUSH r64 (50-57) / POP r64 (58-5F) — 1 byte + REX */
    if ((opcode >= 0x50 && opcode <= 0x5F)) {
        return (DWORD)(p - code);
    }

    /* MOV r64, imm64 (B8-BF with REX.W) */
    if (opcode >= 0xB8 && opcode <= 0xBF) {
        if (hasRex && (rex & 0x08)) {
            /* REX.W: 64-bit immediate */
            return (DWORD)(p - code) + 8;
        }
        /* 32-bit immediate */
        return (DWORD)(p - code) + 4;
    }

    /* MOV r8, imm8 (B0-B7) */
    if (opcode >= 0xB0 && opcode <= 0xB7) {
        return (DWORD)(p - code) + 1;
    }

    /* Short JMP rel8 (EB) */
    if (opcode == 0xEB) {
        return (DWORD)(p - code) + 1;
    }

    /* JMP rel32 (E9) */
    if (opcode == 0xE9) {
        return (DWORD)(p - code) + 4;
    }

    /* CALL rel32 (E8) */
    if (opcode == 0xE8) {
        return (DWORD)(p - code) + 4;
    }

    /* Jcc rel8 (70-7F) */
    if (opcode >= 0x70 && opcode <= 0x7F) {
        return (DWORD)(p - code) + 1;
    }

    /* TEST AL, imm8 */
    if (opcode == 0xA8) {
        return (DWORD)(p - code) + 1;
    }

    /* TEST EAX/RAX, imm32 */
    if (opcode == 0xA9) {
        return (DWORD)(p - code) + 4;
    }

    /* MOV EAX/RAX, moffs (A0-A3) */
    if (opcode >= 0xA0 && opcode <= 0xA3) {
        return (DWORD)(p - code) + (has67 ? 4 : 8);
    }

    /* ALU r/m, imm: 80 /r ib, 81 /r id, 83 /r ib */
    if (opcode == 0x80) {
        /* r/m8, imm8 */
        goto decode_modrm_imm8;
    }
    if (opcode == 0x81) {
        /* r/m32/64, imm32 */
        goto decode_modrm_imm32;
    }
    if (opcode == 0x83) {
        /* r/m32/64, imm8 (sub rsp, 0x28 etc.) */
        goto decode_modrm_imm8;
    }

    /* C6 /0 ib — MOV r/m8, imm8 */
    if (opcode == 0xC6) {
        goto decode_modrm_imm8;
    }

    /* C7 /0 id — MOV r/m32/64, imm32 */
    if (opcode == 0xC7) {
        goto decode_modrm_imm32;
    }

    /* F6 — TEST/NOT/NEG/MUL/DIV r/m8 */
    if (opcode == 0xF6) {
        BYTE modrm = *p;
        BYTE reg = (modrm >> 3) & 7;
        if (reg == 0) {
            /* TEST r/m8, imm8 — has extra imm8 */
            goto decode_modrm_imm8;
        }
        goto decode_modrm;
    }

    /* F7 — TEST/NOT/NEG/MUL/DIV r/m32 */
    if (opcode == 0xF7) {
        BYTE modrm = *p;
        BYTE reg = (modrm >> 3) & 7;
        if (reg == 0) {
            /* TEST r/m32, imm32 */
            goto decode_modrm_imm32;
        }
        goto decode_modrm;
    }

    /* FF — INC/DEC/CALL/JMP/PUSH r/m */
    if (opcode == 0xFF) {
        goto decode_modrm;
    }

    /*
     * Opcodes with ModR/M byte (common ALU, MOV, LEA, TEST, CMP):
     *   00-03 (ADD), 08-0B (OR), 10-13 (ADC), 18-1B (SBB),
     *   20-23 (AND), 28-2B (SUB), 30-33 (XOR), 38-3B (CMP),
     *   84-85 (TEST), 86-87 (XCHG), 88-8B (MOV), 8D (LEA),
     *   63 (MOVSXD), D1/D3 (shift), C0/C1 (shift imm)
     */
    if ((opcode & 0xC4) == 0x00 && (opcode & 0x04) == 0) {
        /* 00,01,02,03, 08,09,0A,0B, 10,11,12,13, 18,19,1A,1B,
           20,21,22,23, 28,29,2A,2B, 30,31,32,33, 38,39,3A,3B */
        goto decode_modrm;
    }

    /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP imm to AL (04,0C,...,3C) */
    if ((opcode & 0xC7) == 0x04) {
        return (DWORD)(p - code) + 1;
    }
    /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP imm32 to EAX (05,0D,...,3D) */
    if ((opcode & 0xC7) == 0x05) {
        return (DWORD)(p - code) + 4;
    }

    if (opcode == 0x63 || opcode == 0x8D) {
        /* MOVSXD, LEA */
        goto decode_modrm;
    }

    if (opcode >= 0x84 && opcode <= 0x8B) {
        /* TEST, XCHG, MOV variants */
        goto decode_modrm;
    }

    if (opcode == 0xD1 || opcode == 0xD3) {
        /* Shift by 1 / by CL */
        goto decode_modrm;
    }

    if (opcode == 0xC0 || opcode == 0xC1) {
        /* Shift by imm8 */
        goto decode_modrm_imm8;
    }

    /* 68 — PUSH imm32 */
    if (opcode == 0x68) {
        return (DWORD)(p - code) + 4;
    }

    /* 6A — PUSH imm8 */
    if (opcode == 0x6A) {
        return (DWORD)(p - code) + 1;
    }

    /* 8F /0 — POP r/m64 */
    if (opcode == 0x8F) {
        goto decode_modrm;
    }

    /* Unknown opcode */
    return 0;

    /* ── ModR/M decoding ──────────────────────────────────────────────── */

decode_modrm_imm8:
    {
        /* Decode ModR/M + SIB + displacement, then add 1 byte imm8 */
        BYTE modrm = *p++;
        BYTE mod = (modrm >> 6) & 3;
        BYTE rm  = modrm & 7;
        BYTE sibBase = 0;

        if (mod == 3) {
            /* Register-direct: no SIB, no disp */
            return (DWORD)(p - code) + 1;
        }

        /* SIB byte present when rm == 4 (not mod 3) */
        if (rm == 4) {
            sibBase = *p & 7;
            p++; /* skip SIB */
        }

        if (mod == 0) {
            if (rm == 5 || (rm == 4 && sibBase == 5)) {
                /* RIP-relative (rm=5) or SIB disp32 (base=5, mod=0) */
                return (DWORD)(p - code) + 4 + 1;
            }
            return (DWORD)(p - code) + 1;
        }
        if (mod == 1) {
            return (DWORD)(p - code) + 1 + 1; /* disp8 + imm8 */
        }
        /* mod == 2 */
        return (DWORD)(p - code) + 4 + 1; /* disp32 + imm8 */
    }

decode_modrm_imm32:
    {
        BYTE modrm = *p++;
        BYTE mod = (modrm >> 6) & 3;
        BYTE rm  = modrm & 7;
        BYTE sibBase = 0;

        if (mod == 3) {
            return (DWORD)(p - code) + 4;
        }

        if (rm == 4) {
            sibBase = *p & 7;
            p++; /* SIB */
        }

        if (mod == 0) {
            if (rm == 5 || (rm == 4 && sibBase == 5)) {
                return (DWORD)(p - code) + 4 + 4;
            }
            return (DWORD)(p - code) + 4;
        }
        if (mod == 1) {
            return (DWORD)(p - code) + 1 + 4;
        }
        return (DWORD)(p - code) + 4 + 4;
    }

decode_modrm:
    {
        BYTE modrm = *p++;
        BYTE mod = (modrm >> 6) & 3;
        BYTE rm  = modrm & 7;
        BYTE sibBase = 0;

        if (mod == 3) {
            return (DWORD)(p - code);
        }

        if (rm == 4) {
            sibBase = *p & 7;
            p++; /* SIB */
        }

        if (mod == 0) {
            if (rm == 5 || (rm == 4 && sibBase == 5)) {
                return (DWORD)(p - code) + 4; /* disp32 */
            }
            return (DWORD)(p - code);
        }
        if (mod == 1) {
            return (DWORD)(p - code) + 1; /* disp8 */
        }
        /* mod == 2 */
        return (DWORD)(p - code) + 4; /* disp32 */
    }
}

/* ── Write a 12-byte absolute JMP ──────────────────────────────────────── */

static void
WriteAbsoluteJmp(BYTE *dest, void *target)
{
    /* mov rax, imm64 */
    dest[0] = 0x48;
    dest[1] = 0xB8;
    *(UINT64 *)(dest + 2) = (UINT64)target;
    /* jmp rax */
    dest[10] = 0xFF;
    dest[11] = 0xE0;
}

/*
 * Write a 14-byte register-safe absolute JMP.
 *
 *   FF 25 00 00 00 00         jmp qword ptr [rip+0]
 *   <8-byte address>          (inline data, not executed)
 *
 * This does NOT clobber any registers — critical for trampoline JMP-backs
 * where EAX holds the syscall number. WriteAbsoluteJmp (mov rax; jmp rax)
 * is fine for the hook entry patch (RAX is caller-saved at function entry)
 * but would destroy EAX in the trampoline, causing STATUS_INVALID_SYSTEM_SERVICE.
 */
#define JMP_RIP_SIZE 14

static void
WriteRipRelativeJmp(BYTE *dest, void *target)
{
    /* jmp qword ptr [rip+0] */
    dest[0] = 0xFF;
    dest[1] = 0x25;
    dest[2] = 0x00;
    dest[3] = 0x00;
    dest[4] = 0x00;
    dest[5] = 0x00;
    /* 8-byte address immediately follows */
    *(UINT64 *)(dest + 6) = (UINT64)target;
}

/* ── Find a free hook slot ─────────────────────────────────────────────── */

static HOOK_ENTRY *
FindFreeSlot(void)
{
    for (int i = 0; i < MAX_HOOKS; i++) {
        if (!g_Hooks[i].Active) {
            return &g_Hooks[i];
        }
    }
    return NULL;
}

/* ── Find an active hook by module + function name ─────────────────────── */

static HOOK_ENTRY *
FindHookByName(const char *moduleName, const char *funcName)
{
    for (int i = 0; i < MAX_HOOKS; i++) {
        if (g_Hooks[i].Active &&
            _stricmp(g_Hooks[i].ModuleName, moduleName) == 0 &&
            strcmp(g_Hooks[i].FunctionName, funcName) == 0) {
            return &g_Hooks[i];
        }
    }
    return NULL;
}

/* ── HookEngineInit ────────────────────────────────────────────────────── */

BOOL
HookEngineInit(void)
{
    if (g_Initialized) {
        return TRUE;
    }

    ZeroMemory(g_Hooks, sizeof(g_Hooks));

    /*
     * Pre-allocate ALL trampoline memory NOW, before any hooks are installed.
     * Once NtAllocateVirtualMemory is hooked, subsequent VirtualAlloc calls
     * go through the detour and fail with ERROR_INVALID_HANDLE under loader lock.
     */
    g_TrampolinePool = (BYTE *)VirtualAlloc(
        NULL, (SIZE_T)MAX_HOOKS * TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!g_TrampolinePool) {
        return FALSE;
    }

    /* Assign each hook slot its pre-allocated trampoline region */
    for (int i = 0; i < MAX_HOOKS; i++) {
        g_Hooks[i].Trampoline = g_TrampolinePool + ((SIZE_T)i * TRAMPOLINE_SIZE);
    }

    /*
     * Pre-unprotect all ntdll code pages BEFORE any hooks are installed.
     *
     * Problem: InstallHook needs to make ntdll code writable (VirtualProtect).
     * But VirtualProtect (kernel32) internally calls NtProtectVirtualMemory
     * (ntdll). Once we hook NtProtectVirtualMemory, all subsequent
     * VirtualProtect calls go through the detour and fail under loader lock.
     *
     * Solution: Make all ntdll executable pages PAGE_EXECUTE_READWRITE now,
     * using VirtualProtect which is safe because no hooks exist yet.
     * InstallHook / RemoveHook then skip VirtualProtect entirely.
     */
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            BYTE *addr = (BYTE *)hNtdll;
            MEMORY_BASIC_INFORMATION mbi;

            while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                /* Stop when we leave ntdll's allocation */
                if (mbi.AllocationBase != (PVOID)hNtdll)
                    break;

                /* Make executable pages writable */
                if (mbi.Protect == PAGE_EXECUTE_READ ||
                    mbi.Protect == PAGE_EXECUTE) {
                    DWORD oldProt;
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                                   PAGE_EXECUTE_READWRITE, &oldProt);
                }

                addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
            }

            g_NtdllUnprotected = TRUE;
            DIAG_LOG("HookEngine: INIT ntdll pages pre-unprotected (%u regions)\r\n",
                     (unsigned)(addr - (BYTE *)hNtdll));
        }
    }

    g_Initialized = TRUE;

    /* No OutputDebugStringA here — runs under loader lock during DllMain */
    return TRUE;
}

/* ── HookEngineCleanup ─────────────────────────────────────────────────── */

void
HookEngineCleanup(void)
{
    if (!g_Initialized) {
        return;
    }

    RemoveAllHooks();

    /* Free the trampoline pool */
    if (g_TrampolinePool) {
        VirtualFree(g_TrampolinePool, 0, MEM_RELEASE);
        g_TrampolinePool = NULL;
    }

    g_Initialized = FALSE;
}

/* ── InstallHook ───────────────────────────────────────────────────────── */

BOOL
InstallHook(
    const char *ModuleName,
    const char *FunctionName,
    void       *DetourFunc,
    void      **OriginalFunc
)
{
    HMODULE     hMod;
    FARPROC     target;
    HOOK_ENTRY *entry;
    BYTE       *trampoline;
    DWORD       stolenSize;
    const BYTE *ip;

    if (!g_Initialized || !ModuleName || !FunctionName ||
        !DetourFunc || !OriginalFunc) {
        return FALSE;
    }

    /* Check if already hooked */
    if (FindHookByName(ModuleName, FunctionName)) {
        return FALSE;
    }

    /* Resolve target function */
    hMod = GetModuleHandleA(ModuleName);
    if (!hMod) {
        return FALSE;
    }

    target = GetProcAddress(hMod, FunctionName);
    if (!target) {
        return FALSE;
    }

    /* Diagnostic: dump first 16 raw bytes BEFORE disassembly */
    {
        const BYTE *fb = (const BYTE *)target;
        DIAG_LOG("HookEngine: PRE  %-28s bytes=[%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X]\r\n",
            FunctionName,
            fb[0],fb[1],fb[2],fb[3],fb[4],fb[5],fb[6],fb[7],
            fb[8],fb[9],fb[10],fb[11],fb[12],fb[13],fb[14],fb[15]);
    }

    /* Find instruction boundary >= JMP_ABS_SIZE bytes */
    stolenSize = 0;
    ip = (const BYTE *)target;

    while (stolenSize < JMP_ABS_SIZE) {
        DWORD len = AkesoEDRGetInstructionLength(ip + stolenSize);
        if (len == 0) {
            DIAG_LOG("HookEngine: FAIL %-28s at offset=%lu opcode=0x%02X\r\n",
                FunctionName, stolenSize, ip[stolenSize]);
            return FALSE;
        }
        stolenSize += len;

        if (stolenSize > MAX_STOLEN_BYTES) {
            return FALSE;
        }
    }

    /* Find a free slot */
    entry = FindFreeSlot();
    if (!entry) {
        DIAG_LOG("HookEngine: SLOT %-28s no free slot\r\n", FunctionName);
        return FALSE;
    }

    /* Use pre-allocated trampoline from pool (assigned in HookEngineInit) */
    trampoline = (BYTE *)entry->Trampoline;
    if (!trampoline) {
        DIAG_LOG("HookEngine: POOL  %-28s trampoline is NULL\r\n", FunctionName);
        return FALSE;
    }

    /* Build trampoline: stolen bytes + register-safe JMP to (target + stolenSize) */
    memcpy(trampoline, (const void *)target, stolenSize);
    WriteRipRelativeJmp(trampoline + stolenSize, (BYTE *)target + stolenSize);

    /* Save original bytes for unhooking */
    memcpy(entry->OriginalBytes, (const void *)target, stolenSize);
    entry->StolenSize  = stolenSize;
    entry->TargetFunc  = (void *)target;
    entry->DetourFunc  = DetourFunc;

    /* Save names for lookup */
    strncpy_s(entry->ModuleName, sizeof(entry->ModuleName),
              ModuleName, _TRUNCATE);
    strncpy_s(entry->FunctionName, sizeof(entry->FunctionName),
              FunctionName, _TRUNCATE);

    /*
     * Patch target: write JMP to detour.
     * ntdll pages were pre-unprotected in HookEngineInit() — no need for
     * VirtualProtect here. This avoids the chicken-and-egg problem where
     * VirtualProtect internally calls NtProtectVirtualMemory which we've
     * already hooked.
     */
    if (!g_NtdllUnprotected) {
        DIAG_LOG("HookEngine: VPROT %-28s ntdll not pre-unprotected\r\n",
                 FunctionName);
        return FALSE;
    }

    WriteAbsoluteJmp((BYTE *)target, DetourFunc);

    /* NOP-pad any remaining bytes beyond the JMP */
    if (stolenSize > JMP_ABS_SIZE) {
        memset((BYTE *)target + JMP_ABS_SIZE, 0x90,
               stolenSize - JMP_ABS_SIZE);
    }

    FlushInstructionCache(GetCurrentProcess(), (void *)target, stolenSize);

    entry->Active = TRUE;
    *OriginalFunc = trampoline;

    DIAG_LOG("HookEngine: OK   %-28s stolen=%lu\r\n",
             FunctionName, stolenSize);

    return TRUE;
}

/* ── RemoveHook ────────────────────────────────────────────────────────── */

BOOL
RemoveHook(
    const char *ModuleName,
    const char *FunctionName
)
{
    HOOK_ENTRY *entry;

    if (!g_Initialized) {
        return FALSE;
    }

    entry = FindHookByName(ModuleName, FunctionName);
    if (!entry) {
        return FALSE;
    }

    /* Restore original bytes — ntdll pages are still PAGE_EXECUTE_READWRITE */
    memcpy(entry->TargetFunc, entry->OriginalBytes, entry->StolenSize);
    FlushInstructionCache(GetCurrentProcess(),
                          entry->TargetFunc, entry->StolenSize);

    /* Trampoline is from pool — don't free individually, just clear slot */
    entry->Active = FALSE;
    entry->TargetFunc = NULL;
    entry->DetourFunc = NULL;
    entry->StolenSize = 0;
    ZeroMemory(entry->OriginalBytes, sizeof(entry->OriginalBytes));
    entry->ModuleName[0] = '\0';
    entry->FunctionName[0] = '\0';

    return TRUE;
}

/* ── RemoveAllHooks ────────────────────────────────────────────────────── */

void
RemoveAllHooks(void)
{
    for (int i = 0; i < MAX_HOOKS; i++) {
        if (g_Hooks[i].Active) {
            /* Restore original bytes — ntdll pages are still RWX */
            memcpy(g_Hooks[i].TargetFunc, g_Hooks[i].OriginalBytes,
                   g_Hooks[i].StolenSize);
            FlushInstructionCache(GetCurrentProcess(),
                                  g_Hooks[i].TargetFunc,
                                  g_Hooks[i].StolenSize);

            /* Trampoline is from pool — don't free individually */
            g_Hooks[i].Active = FALSE;
            g_Hooks[i].TargetFunc = NULL;
            g_Hooks[i].DetourFunc = NULL;
            g_Hooks[i].StolenSize = 0;
        }
    }
}

/* ── HookEngineGetInstallCount ─────────────────────────────────────────── */

int
HookEngineGetInstallCount(void)
{
    int count = 0;
    for (int i = 0; i < MAX_HOOKS; i++) {
        if (g_Hooks[i].Active) {
            count++;
        }
    }
    return count;
}

/* ── P11-T2: Hook state accessors for integrity monitor ───────────────── */

void *
AkesoEDRGetHookTarget(int index)
{
    if (index < 0 || index >= MAX_HOOKS || !g_Hooks[index].Active)
        return NULL;
    return g_Hooks[index].TargetFunc;
}

const char *
AkesoEDRGetHookName(int index)
{
    if (index < 0 || index >= MAX_HOOKS || !g_Hooks[index].Active)
        return NULL;
    return g_Hooks[index].FunctionName;
}

BOOL
AkesoEDRIsHookActive(int index)
{
    if (index < 0 || index >= MAX_HOOKS)
        return FALSE;
    return g_Hooks[index].Active;
}

BOOL
AkesoEDRReinstallHook(int index)
{
    if (index < 0 || index >= MAX_HOOKS || !g_Hooks[index].Active)
        return FALSE;

    HOOK_ENTRY *entry = &g_Hooks[index];

    /* Rebuild the 12-byte absolute JMP: mov rax, <detour>; jmp rax */
    BYTE patch[JMP_ABS_SIZE];
    patch[0] = 0x48;
    patch[1] = 0xB8;
    *(UINT64 *)(patch + 2) = (UINT64)entry->DetourFunc;
    patch[10] = 0xFF;
    patch[11] = 0xE0;

    /* Re-write the target function entry point */
    memcpy(entry->TargetFunc, patch, JMP_ABS_SIZE);

    /* NOP-pad remainder if stolen bytes > 12 */
    if (entry->StolenSize > JMP_ABS_SIZE) {
        memset((BYTE *)entry->TargetFunc + JMP_ABS_SIZE, 0x90,
               entry->StolenSize - JMP_ABS_SIZE);
    }

    FlushInstructionCache(GetCurrentProcess(),
                          entry->TargetFunc, entry->StolenSize);

    DIAG_LOG("HookEngine: REINSTALLED hook[%d] %s\r\n",
             index, entry->FunctionName);
    return TRUE;
}
