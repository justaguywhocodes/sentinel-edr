/*
 * cobaltstrike_beacon.yar
 * Detects Cobalt Strike beacon payloads and shellcode stagers.
 *
 * Cobalt Strike is the most widely used commercial C2 framework,
 * frequently abused by threat actors. Beacons use characteristic
 * configuration blocks, default pipe names, and reflective loading
 * patterns that can be detected with YARA.
 *
 * References:
 *   - https://www.cobaltstrike.com/
 *   - MITRE ATT&CK S0154 (Cobalt Strike)
 *   - SentinelOne CobaltStrike research
 *
 * SentinelPOC Phase 5, Task 4.
 */

rule CobaltStrike_Beacon_Config
{
    meta:
        description = "Cobalt Strike beacon configuration block"
        author      = "SentinelPOC"
        severity    = "Critical"
        mitre       = "S0154"
        phase       = "P5-T4"

    strings:
        /*
         * Beacon config block starts with a 2-byte type indicator
         * followed by 2-byte length, then data. Common config entries:
         *   0x0001 = BeaconType (2 bytes)
         *   0x0002 = Port (2 bytes)
         *   0x0003 = SleepTime (4 bytes)
         *   0x0008 = C2Server (string)
         *   0x000F = SpawnTo (string)
         */

        /* Config block patterns — XOR decoded with common keys */
        $config_raw = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }
        $config_xor_69 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B }
        $config_xor_2e = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C }

        /* Default named pipe patterns (matches constants.h suspicious list) */
        $pipe_msse    = "\\\\.\\pipe\\MSSE-" ascii wide nocase
        $pipe_msagent = "\\\\.\\pipe\\msagent_" ascii wide nocase
        $pipe_postex  = "\\\\.\\pipe\\postex_" ascii wide nocase
        $pipe_status  = "\\\\.\\pipe\\status_" ascii wide nocase

        /* Default User-Agent strings */
        $ua_default_1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" ascii
        $ua_default_2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" ascii
        $ua_default_3 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)" ascii

        /* Beacon watermark / license check strings */
        $license_check = { 2E 2F 2E 2F 2E 2F }

    condition:
        (
            (1 of ($config_*, $license_check)) or
            (2 of ($pipe_*)) or
            (1 of ($pipe_*) and 1 of ($ua_default_*))
        )
}

rule CobaltStrike_Shellcode_Stager
{
    meta:
        description = "Cobalt Strike shellcode stager (reflective loader)"
        author      = "SentinelPOC"
        severity    = "Critical"
        mitre       = "S0154"
        phase       = "P5-T4"

    strings:
        /*
         * Reflective DLL loader — Stephen Fewer's technique.
         * Cobalt Strike beacons use this to load the beacon DLL
         * from memory without touching disk.
         */

        /* x64 reflective loader prologue */
        $reflective_x64 = {
            4D 5A                       /* MZ header check */
            [0-256]
            41 52 65 66 6C 65 63 74     /* "AReflect" partial */
        }

        /* Beacon sleep mask function signatures */
        $sleep_mask_1 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 }
        $sleep_mask_2 = { 49 8B 00 48 89 45 ?? 49 8B 40 08 }

        /* ReflectiveLoader export name */
        $export_reflective = "ReflectiveLoader" ascii
        $export_dllmain    = "_ReflectiveLoader@4" ascii

        /* Cobalt Strike stager: download + inject pattern */
        $stager_wininet = "wininet" ascii
        $stager_httpopen = { FF 15 [4] 89 [1-4] 68 [4] 68 [4] 6A 03 }

        /* x86 shellcode: hash-based API resolution used by CS stagers */
        $api_hash_loop = {
            60                          /* pushad */
            89 E5                       /* mov ebp, esp */
            31 C0                       /* xor eax, eax */
            64 8B 50 30                 /* mov edx, [fs:30h] (PEB) */
            8B 52 0C                    /* mov edx, [edx+0Ch] (Ldr) */
            8B 52 14                    /* mov edx, [edx+14h] (InMemoryOrder) */
        }

    condition:
        (uint16(0) == 0x5A4D or uint8(0) == 0xFC or uint8(0) == 0x4D) and
        (
            (1 of ($reflective_*, $export_reflective, $export_dllmain)) or
            (1 of ($sleep_mask_*)) or
            ($api_hash_loop) or
            ($stager_wininet and $stager_httpopen)
        )
}

rule CobaltStrike_Default_Pipe_Names
{
    meta:
        description = "Binary containing Cobalt Strike default pipe name patterns"
        author      = "SentinelPOC"
        severity    = "High"
        mitre       = "S0154"
        phase       = "P5-T4"

    strings:
        $pipe_msse    = "MSSE-" ascii wide
        $pipe_msagent = "msagent_" ascii wide
        $pipe_postex  = "postex_" ascii wide
        $pipe_postex_ssh = "postex_ssh_" ascii wide

    condition:
        2 of them
}
