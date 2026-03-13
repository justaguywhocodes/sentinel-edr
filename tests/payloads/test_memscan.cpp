/*
 * tests/payloads/test_memscan.cpp
 * Test program for P8-T3 memory scanner verification.
 *
 * Simulates a shellcode injection pattern:
 *   1. VirtualAlloc with PAGE_READWRITE
 *   2. Write YARA-matching content (Mimikatz module strings)
 *   3. VirtualProtect to PAGE_EXECUTE_READ
 *   4. CreateThread pointing at the buffer
 *
 * The hook DLL captures the alloc -> protect -> thread sequence,
 * the sequence rule fires, and the memory scanner finds the
 * YARA-matching content in the unbacked executable region.
 *
 * Usage: test_memscan.exe
 *        (runs, sleeps 30s for scanning, then exits)
 *
 * Build: cl /nologo test_memscan.cpp /Fe:test_memscan.exe
 */

#include <windows.h>
#include <cstdio>
#include <cstring>

/* Dummy thread proc — just sleep and return */
static DWORD WINAPI DummyThread(LPVOID param)
{
    (void)param;
    Sleep(30000);
    return 0;
}

int main()
{
    std::printf("[test_memscan] PID %lu\n", GetCurrentProcessId());

    /*
     * Wait for hook DLL injection.
     * The kernel driver injects sentinel-hook.dll via KAPC when kernel32
     * loads.  By the time main() runs, the DLL *should* be present, but
     * the hooks still need a moment to initialise.  We poll for the
     * module (up to 3 seconds) then add a short settling delay.
     */
    std::printf("[test_memscan] Waiting for hook DLL injection...\n");
    bool hookLoaded = false;
    for (int i = 0; i < 30; i++) {
        if (GetModuleHandleA("sentinel-hook.dll") ||
            GetModuleHandleA("sentinel-hook")) {
            hookLoaded = true;
            break;
        }
        Sleep(100);
    }
    if (hookLoaded) {
        std::printf("[test_memscan] Hook DLL detected, waiting 1s for hooks to settle\n");
        Sleep(1000);
    } else {
        std::printf("[test_memscan] WARNING: Hook DLL not detected after 3s — "
                    "sequence will not be captured\n");
        std::printf("[test_memscan] Make sure sentinel-drv is loaded and "
                    "sentinel-agent is running\n");
    }

    /* 1. Allocate RW memory (triggers NtAllocateVirtualMemory hook) */
    std::printf("[test_memscan] Step 1: VirtualAlloc PAGE_READWRITE\n");
    void* buffer = VirtualAlloc(
        nullptr,
        4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!buffer) {
        std::printf("[test_memscan] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    std::printf("[test_memscan] Allocated at %p\n", buffer);

    /* 2. Write YARA-matching content (Mimikatz module strings).
     *    Mimikatz_Binary rule requires 3+ of: sekurlsa::, kerberos::,
     *    lsadump::, privilege::, crypto::, dpapi::, vault::, token:: */
    std::printf("[test_memscan] Step 2: Write Mimikatz strings\n");
    const char* payload =
        "sekurlsa::logonPasswords\n"
        "kerberos::list\n"
        "lsadump::sam\n"
        "privilege::debug\n"
        "crypto::capi\n";
    memcpy(buffer, payload, strlen(payload) + 1);

    /* 3. Change to RX (triggers NtProtectVirtualMemory hook) */
    std::printf("[test_memscan] Step 3: VirtualProtect PAGE_EXECUTE_READ\n");
    DWORD oldProtect = 0;
    if (!VirtualProtect(buffer, 4096, PAGE_EXECUTE_READ, &oldProtect)) {
        std::printf("[test_memscan] VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    /* 4. Create thread (triggers NtCreateThreadEx hook).
     *    We point at our DummyThread, NOT at the buffer — the buffer
     *    contains ASCII strings, not executable code. The memory scanner
     *    just needs to find the YARA-matching content in the RX region. */
    std::printf("[test_memscan] Step 4: CreateThread\n");
    HANDLE hThread = CreateThread(nullptr, 0, DummyThread, nullptr, 0, nullptr);
    if (!hThread) {
        std::printf("[test_memscan] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    std::printf("[test_memscan] Sequence complete. Sleeping 30s for scanner...\n");
    std::printf("[test_memscan] Expected: Shellcode Runner Pattern alert + "
                "memory scan finding Mimikatz_Binary\n");

    /* Keep alive so the memory scanner can inspect our address space */
    WaitForSingleObject(hThread, 30000);

    /* Cleanup */
    CloseHandle(hThread);
    VirtualFree(buffer, 0, MEM_RELEASE);

    std::printf("[test_memscan] Done.\n");
    return 0;
}
