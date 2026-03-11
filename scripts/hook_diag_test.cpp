/*
 * hook_diag_test.cpp
 * Minimal hook diagnostic — no CRT, writes directly to a file.
 *
 * Compile: cl.exe /MT /Fe:hook_diag_test.exe hook_diag_test.cpp /link kernel32.lib user32.lib
 */

#include <windows.h>

static void WriteLog(HANDLE hFile, const char* msg) {
    DWORD written;
    WriteFile(hFile, msg, (DWORD)lstrlenA(msg), &written, NULL);
    FlushFileBuffers(hFile);
}

static void WriteHex(HANDLE hFile, const char* label, ULONG_PTR val) {
    char buf[128];
    wsprintfA(buf, "%s = 0x%p\r\n", label, (void*)val);
    WriteLog(hFile, buf);
}

int main()
{
    HANDLE hLog = CreateFileA("C:\\SentinelPOC\\hook_test_result.txt",
        GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hLog == INVALID_HANDLE_VALUE) return 99;

    WriteLog(hLog, "=== Hook Diagnostic Test ===\r\n");

    /* Log PID */
    char pidBuf[64];
    wsprintfA(pidBuf, "PID = %lu\r\n", GetCurrentProcessId());
    WriteLog(hLog, pidBuf);

    /* Test 1: Direct NtAllocateVirtualMemory via VirtualAlloc */
    WriteLog(hLog, "[test1] Before VirtualAlloc(RW)...\r\n");

    SetLastError(0);
    void* mem = VirtualAlloc(NULL, 4096,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);

    if (mem) {
        WriteHex(hLog, "[test1] VirtualAlloc OK, addr", (ULONG_PTR)mem);
    } else {
        char errBuf[128];
        wsprintfA(errBuf, "[test1] VirtualAlloc FAILED, GetLastError = %lu\r\n",
                  GetLastError());
        WriteLog(hLog, errBuf);
        WriteLog(hLog, "=== DONE (VirtualAlloc failed) ===\r\n");
        CloseHandle(hLog);
        return 1;
    }

    /* Test 2: VirtualProtect to RX */
    WriteLog(hLog, "[test2] Before VirtualProtect(RX)...\r\n");

    /* Write RET instruction first */
    ((unsigned char*)mem)[0] = 0xC3;

    DWORD oldProt = 0;
    SetLastError(0);
    BOOL ok = VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &oldProt);

    if (ok) {
        char protBuf[128];
        wsprintfA(protBuf, "[test2] VirtualProtect OK, oldProt = 0x%lx\r\n", oldProt);
        WriteLog(hLog, protBuf);
    } else {
        char errBuf[128];
        wsprintfA(errBuf, "[test2] VirtualProtect FAILED, GetLastError = %lu\r\n",
                  GetLastError());
        WriteLog(hLog, errBuf);
    }

    /* Test 3: CreateThread */
    WriteLog(hLog, "[test3] Before CreateThread...\r\n");

    SetLastError(0);
    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);

    if (hThread) {
        WriteLog(hLog, "[test3] CreateThread OK\r\n");
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        WriteLog(hLog, "[test3] Thread completed\r\n");
    } else {
        char errBuf[128];
        wsprintfA(errBuf, "[test3] CreateThread FAILED, GetLastError = %lu\r\n",
                  GetLastError());
        WriteLog(hLog, errBuf);
    }

    VirtualFree(mem, 0, MEM_RELEASE);

    WriteLog(hLog, "=== ALL TESTS DONE ===\r\n");
    CloseHandle(hLog);
    return 0;
}
