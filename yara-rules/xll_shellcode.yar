/*
 * xll_shellcode.yar
 * Detects Excel XLL add-in files containing shellcode indicators.
 *
 * XLL files are PE DLLs loaded by Excel that export xlAutoOpen (or
 * xlAutoAdd). Threat actors abuse this mechanism for initial access
 * by embedding shellcode stagers in XLL payloads. This rule matches
 * PEs that export xlAutoOpen AND contain shellcode-like patterns.
 *
 * References:
 *   - MITRE ATT&CK T1137.006 (Office Add-ins)
 *   - https://www.mandiant.com/resources/xll-files
 *
 * SentinelPOC Phase 5, Task 4.
 */

import "pe"

rule XLL_With_Shellcode_Stager
{
    meta:
        description = "XLL add-in with shellcode stager patterns"
        author      = "SentinelPOC"
        severity    = "High"
        mitre       = "T1137.006"
        phase       = "P5-T4"

    strings:
        /* xlAutoOpen export name (ASCII, as it appears in export table) */
        $export_auto_open = "xlAutoOpen" ascii
        $export_auto_add  = "xlAutoAdd" ascii

        /* VirtualAlloc with PAGE_EXECUTE_READWRITE (0x40) */
        $api_virtualalloc = "VirtualAlloc" ascii
        $api_virtualprotect = "VirtualProtect" ascii

        /* Common shellcode API resolution via hash */
        $hash_ror13_loadlib   = { 72 FE B3 16 }  /* ROR13 hash of LoadLibraryA */
        $hash_ror13_getproc   = { 7C 0D F0 B6 }  /* ROR13 hash of GetProcAddress */

        /* NtAllocateVirtualMemory syscall stub pattern */
        $syscall_ntalloc = { B8 18 00 00 00 0F 05 }  /* mov eax, 0x18; syscall */

        /* Common x64 shellcode prologue patterns */
        $shellcode_x64_1 = { 48 31 C9 48 81 E4 F0 FF FF FF }  /* xor rcx,rcx; and rsp,-10h */
        $shellcode_x64_2 = { FC 48 83 E4 F0 E8 }              /* cld; and rsp,-10h; call */
        $shellcode_x64_3 = { 48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 }

        /* PAGE_EXECUTE_READWRITE constant (0x40) as DWORD push */
        $rwx_push = { 6A 40 }   /* push 0x40 */

    condition:
        pe.is_dll() and
        (1 of ($export_auto_open, $export_auto_add)) and
        (
            (1 of ($api_virtualalloc, $api_virtualprotect) and $rwx_push) or
            (1 of ($hash_ror13_*)) or
            (1 of ($syscall_*)) or
            (1 of ($shellcode_x64_*))
        )
}

rule XLL_Suspicious_Imports
{
    meta:
        description = "XLL add-in with suspicious import combination"
        author      = "SentinelPOC"
        severity    = "Medium"
        mitre       = "T1137.006"
        phase       = "P5-T4"

    strings:
        $export_auto_open = "xlAutoOpen" ascii
        $export_auto_add  = "xlAutoAdd" ascii

    condition:
        pe.is_dll() and
        (1 of ($export_auto_open, $export_auto_add)) and
        (
            /* Process injection pattern */
            (
                pe.imports("kernel32.dll", "VirtualAllocEx") and
                pe.imports("kernel32.dll", "WriteProcessMemory") and
                pe.imports("kernel32.dll", "CreateRemoteThread")
            ) or
            /* Shellcode execution pattern */
            (
                pe.imports("kernel32.dll", "VirtualAlloc") and
                pe.imports("kernel32.dll", "VirtualProtect") and
                pe.imports("kernel32.dll", "CreateThread")
            )
        )
}
