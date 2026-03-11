/*
 * shellcode_test.cpp
 * Test program for P4-T4 sequence detection: alloc(RW) → protect(RX) → CreateThread.
 *
 * Compile: cl.exe /EHsc /MT /Fe:shellcode_test.exe shellcode_test.cpp
 */

#include <windows.h>
#include <cstdio>

/* Flush after every print to avoid buffering issues when hook DLL is active */
#define LOG(fmt, ...) do { \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

/* Simple thread routine: just return 0 */
static DWORD WINAPI DummyThread(LPVOID) { return 0; }

int main()
{
    LOG("[shellcode_test] PID = %lu\n", GetCurrentProcessId());
    LOG("[shellcode_test] Press Enter to start the alloc->protect->thread sequence...\n");
    getchar();

    /* Step 1: VirtualAlloc with PAGE_READWRITE (0x04) */
    LOG("[step 1] Calling VirtualAlloc(RW)...\n");
    void* mem = VirtualAlloc(NULL, 4096,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (!mem) {
        LOG("[step 1] FAILED — error %lu\n", GetLastError());
        return 1;
    }
    LOG("[step 1] OK — addr=%p\n", mem);

    /* Write a tiny RET stub so the thread doesn't crash on garbage */
    ((unsigned char*)mem)[0] = 0xC3;  /* ret */

    /* Small delay so the agent processes step 1 */
    Sleep(200);

    /* Step 2: VirtualProtect to PAGE_EXECUTE_READ (0x20) */
    LOG("[step 2] Calling VirtualProtect(RX)...\n");
    DWORD oldProt = 0;
    BOOL ok = VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &oldProt);
    if (!ok) {
        LOG("[step 2] FAILED — error %lu\n", GetLastError());
        return 1;
    }
    LOG("[step 2] OK — oldProt=0x%lx\n", oldProt);

    Sleep(200);

    /* Step 3: CreateThread pointing at the allocated memory */
    LOG("[step 3] Calling CreateThread...\n");
    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);
    if (!hThread) {
        LOG("[step 3] FAILED — error %lu\n", GetLastError());
        return 1;
    }
    LOG("[step 3] OK — thread handle=%p\n", hThread);

    /* Wait for thread to finish */
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    /* Cleanup */
    VirtualFree(mem, 0, MEM_RELEASE);

    LOG("[shellcode_test] Done. Sequence alert should appear in agent output.\n");
    LOG("[shellcode_test] Check C:\\SentinelPOC\\agent_events.jsonl for the alert.\n");
    return 0;
}
