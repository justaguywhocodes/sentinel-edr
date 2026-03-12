/*
 * mimikatz.yar
 * Detects Mimikatz credential theft tool and variants.
 *
 * Mimikatz is the most widely used credential dumping tool. It extracts
 * plaintext passwords, hashes, PINs, and Kerberos tickets from memory.
 * Variants include compiled builds, PowerShell ports (Invoke-Mimikatz),
 * and custom builds with renamed modules.
 *
 * References:
 *   - https://github.com/gentilkiwi/mimikatz
 *   - MITRE ATT&CK S0002 (Mimikatz)
 *   - MITRE ATT&CK T1003.001 (LSASS Memory)
 *
 * SentinelPOC Phase 5, Task 4.
 */

rule Mimikatz_Binary
{
    meta:
        description = "Mimikatz binary (standard or modified build)"
        author      = "SentinelPOC"
        severity    = "Critical"
        mitre       = "S0002"
        phase       = "P5-T4"

    strings:
        /* Core module command strings */
        $mod_sekurlsa    = "sekurlsa::" ascii wide
        $mod_kerberos    = "kerberos::" ascii wide
        $mod_lsadump     = "lsadump::" ascii wide
        $mod_privilege   = "privilege::" ascii wide
        $mod_crypto      = "crypto::" ascii wide
        $mod_dpapi       = "dpapi::" ascii wide
        $mod_vault       = "vault::" ascii wide
        $mod_token       = "token::" ascii wide

        /* Specific sub-commands */
        $cmd_logonpasswords = "logonPasswords" ascii wide nocase
        $cmd_dcsync         = "dcsync" ascii wide nocase
        $cmd_pth            = "pth" ascii wide nocase
        $cmd_golden         = "golden" ascii wide nocase
        $cmd_silver         = "silver" ascii wide nocase
        $cmd_sam            = "sam" ascii wide nocase

        /* Author / tool identifiers */
        $author_name    = "Benjamin DELPY" ascii wide
        $author_handle  = "gentilkiwi" ascii wide
        $tool_name      = "mimikatz" ascii wide nocase
        $tool_banner    = "  .#####." ascii

    condition:
        (
            /* 3+ module strings = almost certainly mimikatz */
            (3 of ($mod_*)) or
            /* Author + any module */
            ((1 of ($author_*, $tool_name, $tool_banner)) and (1 of ($mod_*))) or
            /* sekurlsa + specific credential commands */
            ($mod_sekurlsa and (1 of ($cmd_logonpasswords, $cmd_pth))) or
            /* lsadump + DC sync or SAM dump */
            ($mod_lsadump and (1 of ($cmd_dcsync, $cmd_sam))) or
            /* Kerberos ticket forging */
            ($mod_kerberos and (1 of ($cmd_golden, $cmd_silver)))
        )
}

rule Mimikatz_PowerShell
{
    meta:
        description = "PowerShell-based Mimikatz (Invoke-Mimikatz)"
        author      = "SentinelPOC"
        severity    = "Critical"
        mitre       = "S0002"
        phase       = "P5-T4"

    strings:
        /* Invoke-Mimikatz script indicators */
        $func_invoke    = "Invoke-Mimikatz" ascii wide nocase
        $func_reflect   = "Invoke-ReflectivePEInjection" ascii wide nocase
        $base64_pe      = "TVqQAAMAAAAEAAAA" ascii   /* Base64 MZ header */

        /* PowerShell mimikatz module strings embedded in script */
        $ps_sekurlsa    = "sekurlsa::logonpasswords" ascii wide nocase
        $ps_privilege   = "privilege::debug" ascii wide nocase
        $ps_kerberos    = "kerberos::list" ascii wide nocase

        /* Common obfuscation patterns */
        $obf_iex        = "IEX" ascii nocase
        $obf_download   = "DownloadString" ascii nocase
        $obf_webclient  = "Net.WebClient" ascii nocase

    condition:
        (
            ($func_invoke and ($base64_pe or $func_reflect)) or
            ($func_invoke and 1 of ($ps_*)) or
            (2 of ($ps_*) and 1 of ($obf_*))
        )
}

rule Mimikatz_Driver_Mimidrv
{
    meta:
        description = "Mimikatz kernel driver (mimidrv.sys)"
        author      = "SentinelPOC"
        severity    = "Critical"
        mitre       = "S0002"
        phase       = "P5-T4"

    strings:
        $drv_name    = "mimidrv" ascii wide nocase
        $drv_device  = "\\Device\\mimikatz" ascii wide
        $drv_symlink = "\\DosDevices\\mimikatz" ascii wide

        /* IoControl codes used by mimidrv */
        $ioctl_1 = { 22 20 00 00 }   /* IOCTL_MIMIDRV_VM_READ */
        $ioctl_2 = { 22 20 04 00 }   /* IOCTL_MIMIDRV_VM_WRITE */
        $ioctl_3 = { 22 20 08 00 }   /* IOCTL_MIMIDRV_PROCESS_PROTECT */

    condition:
        (uint16(0) == 0x5A4D) and
        (
            (1 of ($drv_device, $drv_symlink)) or
            ($drv_name and 2 of ($ioctl_*))
        )
}
