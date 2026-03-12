/*
 * upx_packed.yar
 * Detects UPX-packed PE executables.
 *
 * UPX (Ultimate Packer for eXecutables) is the most common executable
 * packer. While legitimate software uses it, malware authors frequently
 * use UPX (sometimes with modified headers) to evade static analysis
 * and reduce file size. Detection of UPX packing is a useful signal
 * for triage — especially when combined with other indicators.
 *
 * References:
 *   - https://upx.github.io/
 *   - MITRE ATT&CK T1027.002 (Software Packing)
 *
 * SentinelPOC Phase 5, Task 4.
 */

import "pe"

rule UPX_Packed_Standard
{
    meta:
        description = "PE packed with standard UPX (unmodified headers)"
        author      = "SentinelPOC"
        severity    = "Low"
        mitre       = "T1027.002"
        phase       = "P5-T4"

    strings:
        /* UPX section names in PE section headers */
        $section_upx0 = "UPX0" ascii
        $section_upx1 = "UPX1" ascii
        $section_upx2 = "UPX2" ascii

        /* UPX magic marker in overlay / end of file */
        $upx_magic = "UPX!" ascii

    condition:
        pe.number_of_sections >= 3 and
        (
            /* Standard UPX: UPX0 + UPX1 sections with UPX! marker */
            ($section_upx0 and $section_upx1 and $upx_magic) or
            /* Some versions use UPX0 + UPX1 + UPX2 */
            ($section_upx0 and $section_upx1 and $section_upx2)
        )
}

rule UPX_Packed_Modified
{
    meta:
        description = "PE packed with UPX but section names modified to evade detection"
        author      = "SentinelPOC"
        severity    = "Medium"
        mitre       = "T1027.002"
        phase       = "P5-T4"

    strings:
        /*
         * UPX unpacking stub signatures (survive header modification).
         * These patterns appear in the entry point code regardless of
         * whether the attacker renamed UPX0/UPX1 sections.
         */

        /* x86 UPX decompression stub */
        $stub_x86_1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $stub_x86_2 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 EB 0B }

        /* x64 UPX decompression stub */
        $stub_x64_1 = { 53 56 57 55 48 8D 35 ?? ?? ?? ?? 48 8D 3D }
        $stub_x64_2 = { 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 35 }

        /* UPX version string (often left even when headers modified) */
        $version_str = "$Id: UPX" ascii
        $info_str    = "UPX!" ascii

    condition:
        (uint16(0) == 0x5A4D) and   /* MZ header */
        (
            /* Modified UPX: stub pattern without standard section names */
            (
                (1 of ($stub_x86_*, $stub_x64_*)) and
                not for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == "UPX0" or
                    pe.sections[i].name == "UPX1"
                )
            ) or
            /* Version or magic string present but sections renamed */
            (
                ($version_str or $info_str) and
                not for any i in (0..pe.number_of_sections - 1) : (
                    pe.sections[i].name == "UPX0"
                )
            )
        )
}
