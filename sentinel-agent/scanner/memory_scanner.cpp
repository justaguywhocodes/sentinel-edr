/*
 * sentinel-agent/scanner/memory_scanner.cpp
 * Process memory scanner implementation.
 *
 * Enumerates a target process's virtual address space to find
 * MEM_PRIVATE regions with executable protection — the hallmark
 * of shellcode injection, reflective DLL loading, and in-memory
 * payloads. Each qualifying region is read and scanned against
 * YARA rules.
 *
 * Triggered by the sequence rule engine when a shellcode injection
 * pattern is detected (alloc RW → protect RX → create thread).
 *
 * P8-T3: Memory Scanner.
 * Book reference: Chapter 9 — Scanners.
 */

#include "scanner/memory_scanner.h"
#include "scanner/yara_scanner.h"
#include "constants.h"

#include <cstdio>
#include <cstring>
#include <vector>

/* ── Init / Shutdown ─────────────────────────────────────────────────────── */

void
MemoryScanner::Init(YaraScanner* scanner)
{
    m_scanner = scanner;
}

void
MemoryScanner::Shutdown()
{
    m_scanner = nullptr;
}

bool
MemoryScanner::IsReady() const
{
    return m_scanner != nullptr && m_scanner->IsReady();
}

/* ── Helper: is protection executable? ───────────────────────────────────── */

static bool
IsExecutableProtection(DWORD protect)
{
    const DWORD execBits = PAGE_EXECUTE
                         | PAGE_EXECUTE_READ
                         | PAGE_EXECUTE_READWRITE
                         | PAGE_EXECUTE_WRITECOPY;
    return (protect & execBits) != 0;
}

/* ── ScanProcess ─────────────────────────────────────────────────────────── */

bool
MemoryScanner::ScanProcess(ULONG targetPid, SENTINEL_EVENT& alertOut)
{
    if (!IsReady()) {
        return false;
    }

    /* Open the target process for memory inspection */
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        targetPid);

    if (!hProcess) {
        std::printf("[MemScan] Cannot open PID %lu (error %lu)\n",
                    targetPid, GetLastError());
        return false;
    }

    std::printf("[MemScan] Scanning PID %lu for unbacked executable regions\n",
                targetPid);

    MEMORY_BASIC_INFORMATION mbi = {};
    const uint8_t* address = nullptr;
    int regionsScanned = 0;
    bool foundMatch = false;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        /* Advance to next region for next iteration */
        const uint8_t* nextAddress = static_cast<const uint8_t*>(mbi.BaseAddress)
                                   + mbi.RegionSize;

        /* Filter: committed, private (not image-backed), executable */
        if (mbi.State  == MEM_COMMIT &&
            mbi.Type   == MEM_PRIVATE &&
            IsExecutableProtection(mbi.Protect) &&
            mbi.RegionSize > 0 &&
            mbi.RegionSize <= SENTINEL_SCAN_MAX_REGION_SIZE)
        {
            /* Read region contents */
            std::vector<uint8_t> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            BOOL ok = ReadProcessMemory(
                hProcess,
                mbi.BaseAddress,
                buffer.data(),
                mbi.RegionSize,
                &bytesRead);

            if (ok && bytesRead > 0) {
                regionsScanned++;

                SENTINEL_SCANNER_EVENT result = {};

                if (m_scanner->ScanBuffer(buffer.data(), bytesRead, result)) {
                    if (result.IsMatch) {
                        /* Build the alert event */
                        SentinelEventInit(&alertOut, SentinelSourceScanner,
                                          SentinelSeverityHigh);
                        alertOut.ProcessCtx.ProcessId = targetPid;

                        auto& scan         = alertOut.Payload.Scanner;
                        scan.ScanType      = SentinelScanMemory;
                        scan.IsMatch       = TRUE;
                        scan.TargetProcessId = targetPid;

                        /* Format address range in TargetPath */
                        _snwprintf_s(scan.TargetPath, SENTINEL_MAX_PATH,
                                     _TRUNCATE,
                                     L"PID %lu @ 0x%p (size: %zu)",
                                     targetPid, mbi.BaseAddress,
                                     bytesRead);

                        strncpy_s(scan.YaraRule, sizeof(scan.YaraRule),
                                  result.YaraRule, _TRUNCATE);

                        foundMatch = true;
                        break;  /* Report first match */
                    }
                }
            }
        }

        address = nextAddress;

        /* Safety: stop if we've wrapped around or hit high addresses */
        if (nextAddress <= static_cast<const uint8_t*>(mbi.BaseAddress)) {
            break;
        }
    }

    CloseHandle(hProcess);

    std::printf("[MemScan] PID %lu: scanned %d private executable regions, "
                "match=%s\n",
                targetPid, regionsScanned,
                foundMatch ? "YES" : "no");

    return foundMatch;
}
