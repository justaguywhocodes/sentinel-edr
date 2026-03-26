/*
 * akesoedr-hook/evasion_detect.h
 * P11-T1: Direct syscall + ntdll remap detection.
 *
 * Provides runtime checks for common EDR evasion techniques:
 *   1. Return address validation — detects calls originating outside
 *      known modules (ntdll, kernel32, kernelbase), indicating direct
 *      syscall tools like SysWhispers or HellsGate.
 *   2. ntdll integrity verification — detects when an attacker remaps
 *      a fresh copy of ntdll.dll to bypass inline hooks.
 */

#ifndef AKESOEDR_EVASION_DETECT_H
#define AKESOEDR_EVASION_DETECT_H

#include <windows.h>

/*
 * AkesoEDREvasionInit
 *   Cache module base addresses and compute ntdll .text section CRC.
 *   Must be called AFTER HookEngineInit() (ntdll pages already RW)
 *   and BEFORE hooks are installed.
 */
void AkesoEDREvasionInit(void);

/*
 * AkesoEDRCheckReturnAddress
 *   Returns TRUE if the return address falls within a known legitimate
 *   module (ntdll, kernel32, kernelbase, or the hook DLL itself).
 *   Returns FALSE if the address is suspicious — indicates direct syscall,
 *   shellcode, or call from unmapped/unknown region.
 */
BOOL AkesoEDRCheckReturnAddress(ULONG_PTR retAddr);

/*
 * AkesoEDRVerifyNtdllIntegrity
 *   Recomputes CRC32 of ntdll's .text section and compares against
 *   the baseline captured during init.
 *   Returns TRUE if intact, FALSE if modified (remap or unhooking).
 *
 *   Note: Our own hooks modify ntdll .text, so the baseline is captured
 *   BEFORE hooks are installed. After hooks are installed, this function
 *   verifies that ntdll hasn't been further modified (i.e., an attacker
 *   hasn't remapped a clean copy to remove our hooks).
 *   We recapture the baseline AFTER hooks are installed via
 *   AkesoEDREvasionRecaptureBaseline().
 */
BOOL AkesoEDRVerifyNtdllIntegrity(void);

/*
 * AkesoEDREvasionRecaptureBaseline
 *   Recompute the ntdll .text CRC after hooks are installed.
 *   This becomes the "expected" state — hooks present.
 *   Any future change means either unhooking or remap.
 */
void AkesoEDREvasionRecaptureBaseline(void);

#endif /* AKESOEDR_EVASION_DETECT_H */
