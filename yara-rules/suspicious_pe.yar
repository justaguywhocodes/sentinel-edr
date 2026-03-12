/*
 * suspicious_pe.yar
 * General suspicious PE executable indicators.
 *
 * Detects PEs with characteristics commonly seen in malware:
 * RWX sections, process injection import combinations, and
 * section names associated with known packers/crypters.
 *
 * These rules are lower-confidence than tool-specific signatures
 * and should be used as triage indicators rather than definitive
 * detections.
 *
 * References:
 *   - MITRE ATT&CK T1055 (Process Injection)
 *   - MITRE ATT&CK T1027.002 (Software Packing)
 *
 * SentinelPOC Phase 5, Task 4.
 */

import "pe"
import "math"

rule PE_RWX_Section
{
    meta:
        description = "PE with Read-Write-Execute section (common in packed/injected code)"
        author      = "SentinelPOC"
        severity    = "Medium"
        mitre       = "T1027.002"
        phase       = "P5-T4"

    condition:
        pe.number_of_sections > 0 and
        for any i in (0..pe.number_of_sections - 1) : (
            /* IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE */
            (pe.sections[i].characteristics & 0xE0000000) == 0xE0000000 and
            /* Ignore tiny sections (resource stubs, etc.) */
            pe.sections[i].raw_data_size > 512
        )
}

rule PE_Process_Injection_Imports
{
    meta:
        description = "PE importing classic process injection API combination"
        author      = "SentinelPOC"
        severity    = "High"
        mitre       = "T1055.001"
        phase       = "P5-T4"

    condition:
        pe.number_of_sections > 0 and
        (
            /* Classic CreateRemoteThread injection */
            (
                pe.imports("kernel32.dll", "OpenProcess") and
                pe.imports("kernel32.dll", "VirtualAllocEx") and
                pe.imports("kernel32.dll", "WriteProcessMemory") and
                pe.imports("kernel32.dll", "CreateRemoteThread")
            ) or
            /* NtCreateThreadEx-based injection */
            (
                pe.imports("kernel32.dll", "OpenProcess") and
                pe.imports("kernel32.dll", "VirtualAllocEx") and
                pe.imports("kernel32.dll", "WriteProcessMemory") and
                pe.imports("ntdll.dll", "NtCreateThreadEx")
            ) or
            /* APC injection pattern */
            (
                pe.imports("kernel32.dll", "OpenProcess") and
                pe.imports("kernel32.dll", "VirtualAllocEx") and
                pe.imports("kernel32.dll", "WriteProcessMemory") and
                pe.imports("kernel32.dll", "QueueUserAPC")
            )
        )
}

rule PE_Suspicious_Section_Names
{
    meta:
        description = "PE with section names associated with known packers or crypters"
        author      = "SentinelPOC"
        severity    = "Medium"
        mitre       = "T1027.002"
        phase       = "P5-T4"

    condition:
        pe.number_of_sections > 0 and
        for any i in (0..pe.number_of_sections - 1) : (
            /* Themida / WinLicense */
            pe.sections[i].name == ".themida" or
            pe.sections[i].name == ".winlice" or
            /* VMProtect */
            pe.sections[i].name == ".vmp0" or
            pe.sections[i].name == ".vmp1" or
            pe.sections[i].name == ".vmp2" or
            /* ASPack */
            pe.sections[i].name == ".aspack" or
            pe.sections[i].name == ".adata" or
            /* Enigma Protector */
            pe.sections[i].name == ".enigma1" or
            pe.sections[i].name == ".enigma2" or
            /* PECompact */
            pe.sections[i].name == "PEC2TO" or
            pe.sections[i].name == "PEC2MO" or
            /* MPRESS */
            pe.sections[i].name == ".MPRESS1" or
            pe.sections[i].name == ".MPRESS2"
        )
}

rule PE_High_Entropy_Section
{
    meta:
        description = "PE with high-entropy section suggesting encryption or packing"
        author      = "SentinelPOC"
        severity    = "Low"
        mitre       = "T1027.002"
        phase       = "P5-T4"

    condition:
        pe.number_of_sections > 0 and
        for any i in (0..pe.number_of_sections - 1) : (
            /* Entropy > 7.0 on a section > 4KB is suspicious */
            pe.sections[i].raw_data_size > 4096 and
            math.entropy(
                pe.sections[i].raw_data_offset,
                pe.sections[i].raw_data_size
            ) > 7.0
        )
}
