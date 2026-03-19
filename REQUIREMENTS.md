# SentinelEDR — Requirements Document v1.0

**A Proof-of-Concept Endpoint Detection & Response Agent for Windows x64**

Version 1.0 — Initial Requirements + Implementation Phases | March 2026

> Architecture derived from sensor models in *Evading EDR* by Matt Hand (No Starch Press, 2023)

---

# PART I: REQUIREMENTS & ARCHITECTURE

## 1. Executive Summary

SentinelEDR is a proof-of-concept Endpoint Detection and Response (EDR) agent for 64-bit Windows, built entirely in C/C++. Its purpose is to serve as a purple-team training platform: a fully transparent, open-architecture EDR whose internals can be studied, attacked, and improved upon by both offensive and defensive security practitioners.

The project's design is directly informed by the sensor architecture described in Matt Hand's *Evading EDR* (No Starch Press, 2023). Each sensor component the book deconstructs—from kernel callback routines and userland function hooks to ETW consumers, minifilters, and AMSI providers—becomes a discrete, testable module within SentinelEDR. The Chapter 13 case study (a full detection-aware attack chain from initial access through exfiltration) serves as the primary integration test plan.

This document is organized into two parts. Part I captures the system requirements: what SentinelEDR must do, how its components are structured, and the acceptance criteria for each sensor. Part II breaks the implementation into phased tasks sized for iterative development with Claude Code.

## 2. Project Goals & Non-Goals

### 2.1 Goals

- Build a working, modular EDR agent that implements the sensor components described in *Evading EDR* Chapters 1–12.
- Provide a vendor-agnostic reference implementation that maps to the book's "Basic," "Intermediate," and "Advanced" agent design tiers.
- Detect the full attack chain from Chapter 13 (XLL payload delivery, local shellcode execution, C2 establishment, persistence via preview handlers, Seatbelt-style recon, privilege escalation, lateral movement, and file exfiltration).
- Serve as a purple-team training tool where red teamers can test evasion techniques against a fully instrumented, source-available EDR.
- Generate structured telemetry (JSON) that can be piped to a SIEM, ELK stack, or a simple local dashboard for analysis.
- Maintain a clean C/C++ codebase with minimal external dependencies, buildable with the Windows Driver Kit (WDK) and Visual Studio.

### 2.2 Non-Goals (v1)

- Production deployment or commercial use. SentinelEDR is a research and training tool.
- WHQL driver signing or ELAM certification (test-signing mode is acceptable for v1).
- Cloud-based backend analytics, machine learning, or global reputation scoring.
- Cross-platform support (Linux/macOS agents are out of scope).
- Hypervisor-based detection or adversary deception (classified as "Advanced" in Ch. 1, deferred to v2+).
- Remote management server (v1 is local-only; see v2 Roadmap in Part II).

## 3. System Architecture

The architecture follows the "Intermediate" agent design from Chapter 1, with hooks into the "Advanced" tier where feasible without ELAM/PPL. The system is composed of four primary binaries and a shared telemetry protocol.

### 3.1 Component Overview

| Component | Mode | Responsibility |
|-----------|------|----------------|
| **sentinel-drv** `.sys` | Kernel | Registers all kernel callback routines (process, thread, object, image-load, registry), minifilter for filesystem I/O, WFP callout for network filtering. Communicates telemetry to agent via filter communication port. |
| **sentinel-hook** `.dll` | User (injected) | Function-hooking DLL injected into monitored processes via KAPC injection. Hooks ntdll exports using inline trampoline hooks. |
| **sentinel-agent** `.exe` | User (service) | Central agent service. Aggregates telemetry from driver, hooking DLL, ETW consumers, and scanner. Runs detection rule engine. Emits alerts to log sink. Manages AMSI provider registration. |
| **sentinel-cli** `.exe` | User (console) | Management CLI for querying agent status, reviewing alerts, triggering scans, loading rules, and pulling signature updates from Git. |

### 3.2 Telemetry Protocol

All sensor components emit telemetry as JSON-structured events over a named pipe (`\\.\pipe\SentinelTelemetry`). Each event includes a common envelope: **event_id** (UUID v4), **timestamp** (high-resolution), **source** (sensor identifier), **process_context** (PID, PPID, image path, command line, user SID, session ID, integrity level), and **payload** (sensor-specific data).

### 3.3 Detection Engine

The agent implements a rule-based detection engine inspired by the Elastic detection rules referenced in Chapter 1. Rules are defined in YAML and support three evaluation models: **single-event rules** (match on one event, e.g., file hash match), **sequence rules** (ordered events within a time window, e.g., alloc→protect→thread), and **threshold rules** (event count exceeds threshold in window). Each rule specifies an action: LOG, BLOCK, or DECEIVE.

### 3.4 Signature Updates

Detection rules (YAML) and YARA signatures are stored in Git repositories. `sentinel-cli rules update` pulls latest rules, validates YAML/YARA, and triggers hot-reload. Validation failure rolls back the pull automatically.

## 4. Sensor Component Requirements

### 4.1 Kernel Callback Driver (Chapters 3–5)

#### 4.1.1 Process & Thread Notifications (Ch. 3)

| Aspect | Requirement |
|--------|-------------|
| **Callback API** | `PsSetCreateProcessNotifyRoutineEx` for process creation/termination. `PsSetCreateThreadNotifyRoutineEx` for thread creation/termination. |
| **Telemetry** | Process: image path, command line, PID, PPID, creating thread ID, token info (SID, integrity), PE metadata. Thread: TID, start address, owning PID, remote vs. local flag. |
| **Detection targets** | Suspicious parent-child relationships. Remote thread creation into sensitive processes. fork&run injection. |
| **Test evasions** | Command-line tampering. PPID spoofing. Process hollowing/herpaderping. fork&run injection. |

#### 4.1.2 Object Notifications (Ch. 4)

| Aspect | Requirement |
|--------|-------------|
| **Callback API** | `ObRegisterCallbacks` for Process and Thread object types. |
| **Telemetry** | Source PID/TID, target PID, requested/granted access mask, operation type. |
| **Detection targets** | Handle requests to lsass.exe, csrss.exe. Credential dumping signatures. |
| **Test evasions** | Handle theft. Racing the callback routine. |

#### 4.1.3 Image-Load & Registry Notifications (Ch. 5)

| Aspect | Requirement |
|--------|-------------|
| **Callback API** | `PsSetLoadImageNotifyRoutineEx` for image loads. `CmRegisterCallbackEx` for registry. |
| **Telemetry** | Image: path, base address, size, signing status, PID. Registry: operation type, key path, value name, data. |
| **Detection targets** | Unsigned DLLs in sensitive processes. Persistence registry keys. Preview handler registration (Ch. 13). |
| **Test evasions** | Tunneling tools. Callback entry overwrites via vulnerable driver. |
| **KAPC injection** | Image-load triggers injection of sentinel-hook.dll via kernel APC queuing. |

### 4.2 Filesystem Minifilter Driver (Chapter 6)

| Aspect | Requirement |
|--------|-------------|
| **Altitude** | FSFilter Anti-Virus range (320000–329998). |
| **Operations** | IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION, IRP_MJ_CREATE_NAMED_PIPE. |
| **Telemetry** | File path, operation, PID, SHA-256 hash (async), file size, timestamp. |
| **Detection targets** | Malware drops. Ransomware patterns. Named pipe C2. XLL writes (Ch. 13). |
| **Test evasions** | Minifilter unloading. Filter interference. Pre/post callback ordering issues. |

### 4.3 Network Filter Driver (Chapter 7)

| Aspect | Requirement |
|--------|-------------|
| **Framework** | WFP callout driver. |
| **Layers** | Outbound/inbound transport V4/V6, stream V4. |
| **Telemetry** | Source/dest IP+port, protocol, PID, direction, bytes, domain. |
| **Detection targets** | C2 beaconing. Lateral movement (SMB, WMI, WinRM). DNS tunneling. |
| **Test evasions** | Slow beaconing. Domain fronting. Common port abuse. |

### 4.4 Function-Hooking DLL (Chapter 2)

| Aspect | Requirement |
|--------|-------------|
| **Injection** | KAPC injection from driver image-load callback. |
| **Technique** | Inline trampoline hooks on ntdll.dll exports. |
| **Hooked functions** | NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory, NtCreateThreadEx, NtMapViewOfSection, NtUnmapViewOfSection, NtQueueApcThread, NtCreateSection, NtOpenProcess, NtSuspendThread, NtResumeThread. |
| **Telemetry** | Function name, parameters, calling module, return address, stack hash. |
| **Detection targets** | Injection chains. RWX allocations. RW→RX protection changes. |
| **Test evasions** | Direct syscalls. SSN resolution (Hell's/Halo's Gate). ntdll remapping. Unhooking. |

### 4.5 ETW Consumer (Chapter 8)

| Aspect | Requirement |
|--------|-------------|
| **Providers** | Kernel-Process, DotNETRuntime, PowerShell, AMSI, DNS-Client, Security-Kerberos, RPC, Services. |
| **Implementation** | Real-time trace session. Callback-driven parsing per provider. |
| **Detection targets** | .NET assembly loads. PowerShell script blocks. DNS queries. Kerberoasting. Service install. |
| **Test evasions** | ETW patching. Trace session tampering. Provider disabling. Reflection-based .NET loading. |

### 4.6 Scanner Engine (Chapter 9)

| Aspect | Requirement |
|--------|-------------|
| **Models** | On-access (minifilter trigger), on-demand (CLI/scheduled), memory (detection engine trigger). |
| **Engine** | libyara static library. Hot-reload. SHA-256 hash lookup. PE metadata extraction. |
| **Memory scanning** | NtReadVirtualMemory on executable regions. Detect unbacked executable memory. |
| **Test evasions** | Signature mutation. XOR obfuscation. PE header stomping. Non-image-backed execution. |

### 4.7 AMSI Provider (Chapter 10)

| Aspect | Requirement |
|--------|-------------|
| **Implementation** | COM IAntimalwareProvider. Receives scans from PowerShell, .NET, VBScript, JScript, VBA, WSH. |
| **Scan logic** | Pattern matching + YARA on content buffers. |
| **Detection targets** | Obfuscated PowerShell. In-memory .NET loading. VBA macros. AMSI bypass attempts. |
| **Test evasions** | String obfuscation. AmsiScanBuffer patching. Patchless bypass. amsiInitFailed overwrite. |

## 5. Integration Test Plan (Chapter 13 Attack Chain)

| Phase | Attack Action | Expected Sensor Response |
|-------|--------------|------------------------|
| Initial Access | XLL delivered + opened | Minifilter: .xll write. Scanner: on-access. Process callback: excel.exe + XLL cmdline. |
| Execution | Shellcode runner: alloc→copy→protect→thread | Hook DLL: NtAlloc/NtProtect/NtCreateThread. Sequence rule fires. |
| C2 | HTTPS beacon | Network filter: outbound 443. DNS ETW: C2 domain. |
| Persistence | Preview handler COM reg + DLL drop | Registry callback: COM key. Minifilter: DLL write. Image-load: unsigned DLL in explorer. |
| Recon | Seatbelt (.NET) reflective load | ETW .NET: assembly load. AMSI: content scan. |
| Priv Escalation | File handler hijack | Object callback: privileged handle. Process callback: elevated child. |
| Lateral Movement | SMB enum + file copy | Network filter: port 445. ETW RPC. Process callback: net.exe. |
| Exfiltration | File copy over C2 | Network filter: large outbound. Minifilter: target file reads. Sequence: read + network. |

## 6. Feature Priority Matrix

| Feature | Priority | Phase | Notes |
|---------|----------|-------|-------|
| Process creation callbacks | P0 — Critical | Phase 1 | Foundation of all process-level detection |
| Thread creation callbacks | P0 — Critical | Phase 1 | Remote thread injection detection |
| Image-load + KAPC injection | P0 — Critical | Phase 2 | Inject hooking DLL |
| ntdll function hooking DLL | P0 — Critical | Phase 3 | Primary userland telemetry |
| YARA file scanner | P0 — Critical | Phase 8 | Static detection baseline |
| Agent service + IPC | P0 — Critical | Phase 4 | Telemetry backbone |
| Object handle callbacks | P1 — High | Phase 2 | Credential dump detection |
| Registry callbacks | P1 — High | Phase 2 | Persistence detection |
| Filesystem minifilter | P1 — High | Phase 5 | File + named pipe detection |
| WFP network filter | P1 — High | Phase 6 | C2 + lateral movement |
| ETW consumer (8 providers) | P1 — High | Phase 7 | .NET/PS/DNS/Kerberos/RPC |
| AMSI provider | P1 — High | Phase 7 | Script-level detection |
| Memory scanner | P1 — High | Phase 8 | Unbacked executable detection |
| Sequence rules | P1 — High | Phase 4 | Behavioral chains |
| Git-based signature updates | P1 — High | Phase 9 | Rule distribution |
| Self-protection | P2 — Medium | Phase 11 | Sensor blinding detection |
| Direct syscall detection | P2 — Medium | Phase 11 | ntdll bypass detection |
| Telemetry cross-validation | P2 — Medium | Phase 11 | Redundancy |
| Remote management server | P3 — Low | v2 | See v2 Roadmap |
| RPC filters | P3 — Low | v2+ | DCSync/PetitPotam |
| Nirvana hooks | P3 — Low | v2+ | Syscall return interception |
| Hypervisor | P3 — Low | v2+ | Anti-exploit/ransomware |

## 7. Build & Development Environment

### 7.1 Toolchain

- **Compiler:** MSVC (VS 2022) + WDK for kernel components.
- **Build system:** CMake with WDK integration.
- **Language:** C17 for driver, C++20 for agent/CLI.
- **Analysis:** MSVC /analyze, Driver Verifier, SDV.
- **Debugging:** WinDbg (kdnet) for kernel, VS debugger for user-mode.

### 7.2 Test Environment

- **Target VMs:** Windows 10 22H2 + Windows 11 23H2 (x64), test-signing enabled.
- **Kernel debugging:** Two-VM setup, WinDbg host via kdnet.
- **Attack tooling:** Custom XLL (Ch. 13), Cobalt Strike/Sliver, Seatbelt, Rubeus, Mimikatz, SharpHound.
- **Telemetry sink:** ELK stack or JSON file sink for v1.

### 7.3 Repository Structure

`sentinel-drv/` (kernel driver) · `sentinel-hook/` (hooking DLL) · `sentinel-agent/` (agent service) · `sentinel-cli/` (CLI) · `common/` (shared headers) · `rules/` (YAML, Git-managed) · `yara-rules/` (YARA, Git-managed) · `tests/` (integration tests) · `scripts/` (build/install helpers) · `docs/` (architecture + API docs)

## 8. Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Kernel bugs → BSOD | High | Driver Verifier, pool tagging, IRQL discipline, incremental per-callback testing. |
| Test-signing limits applicability | Medium | Acceptable for v1. EV signing for v2+. |
| Sensor performance overhead | Medium | Async processing, worker threads for hashing, configurable granularity. |
| KAPC fails on protected processes | Medium | Exclude PPL. Use callbacks + ETW for visibility. |
| Evasions evolve faster than rules | Low | By design — training platform, not commercial product. |
| No EtwTi without ELAM | Low | Standard ETW covers significant telemetry. ELAM deferred to v2. |

## 9. References

- Hand, Matt. *Evading EDR.* No Starch Press, 2023.
- Microsoft WDK docs · Win32 API docs · Elastic Detection Rules · YARA docs · MITRE ATT&CK
- Johnson, Jonathan. "Evadere Classifications." SpecterOps, 2021.
- Atkinson, Jared. "Funnel of Fidelity." SpecterOps.
- Open-source: emryll/EDR, 0xrawsec/whids, wavestone-cdt/EDRSandblast.

---

# PART II: IMPLEMENTATION PHASES

## 10. How To Use Part II With Claude Code

Part II breaks Part I's requirements into 49 discrete tasks across 12 phases, each sized for a single Claude Code session.

### Workflow

1. Open a Claude Code session and provide the task ID (e.g., "Implement task P1-T3") with this document as context.
2. Claude Code generates the implementation. Review against acceptance criteria.
3. Build/test. If criteria pass, commit and move to next task.
4. If a task fails, stay in session and refine. Tasks are dependency-ordered within each phase.

### Complexity Ratings

- **S (Small):** <200 lines, one session. Headers, configs, scripts.
- **M (Medium):** 200–600 lines, one session. Single component with moderate logic.
- **L (Large):** 500–1500 lines, 2–3 sessions. Multi-file, kernel/user interaction, IPC.
- **XL (Extra Large):** Cross-component integration, 2–4 sessions.

### Session Tips

- Paste the relevant phase section at session start.
- Reference `common/` headers so Claude Code knows where types live.
- For kernel tasks: remind of WDK constraints (C17, no exceptions, no STL, IRQL discipline).
- Ensure prior task output is committed before starting dependent tasks.

---

## Phase 0: Project Scaffolding

**Goal:** Monorepo, build system, shared headers, IPC protocol. **Book:** Ch. 1.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P0-T1 | Init monorepo: CMakeLists.txt, .gitignore, README, LICENSE. CMake detects WDK. | Top-level + subdirectory CMakeLists.txt stubs | `cmake -B build` succeeds. Stubs compile. | S |
| P0-T2 | Shared telemetry schema: event_id, timestamp, source enum, process context, tagged payload union. | `common/telemetry.h` | Compiles in kernel (C17) and user (C++20) mode. All Ch. 2–12 event types covered. | M |
| P0-T3 | IPC protocol: named pipe + filter port framing. 4-byte length prefix. Handshake. | `common/ipc.h`, `common/ipc_serialize.h` | Compiles both modes. Serialization round-trips correctly. | M |
| P0-T4 | Constants: device name, pipe names, IOCTLs, altitude, WFP GUIDs. | `common/constants.h` | No magic numbers in subsequent code. | S |
| P0-T5 | Driver install/uninstall PowerShell scripts + test-signing setup. | `scripts/*.ps1` | Run clean on Win10/11 x64 VM. | S |

---

## Phase 1: Kernel Driver — Process & Thread Callbacks

**Goal:** Driver skeleton + process/thread callbacks. **Book:** Ch. 3.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P1-T1 | DriverEntry/Unload, device object, filter communication port. | `sentinel-drv/main.c`, `comms.c`, `comms.h` | Load/unload clean. Port visible to user-mode. | M |
| P1-T2 | Process creation callback (PsSetCreateProcessNotifyRoutineEx). Full event: image, cmdline, PID, PPID, token, PE metadata. | `callbacks_process.c/.h` | notepad.exe → event on port. All fields non-null. <50ms. | L |
| P1-T3 | Thread creation callback. Remote thread flagging. | `callbacks_thread.c/.h` | Process + thread events. CreateRemoteThread → remote=true. | M |
| P1-T4 | Test consumer: connect to filter port, print JSON to stdout. | `tests/test_consumer.c` | JSON stream on process launch. Clean disconnect. | M |

---

## Phase 2: Object, Image-Load, Registry Callbacks

**Goal:** Complete kernel callback suite + KAPC injection. **Book:** Ch. 4–5.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P2-T1 | Object callbacks (ObRegisterCallbacks). Protected process list. | `callbacks_object.c/.h` | lsass handle open → event. Non-protected filtered. | L |
| P2-T2 | Image-load callback. Signing status. Per-process module table. | `callbacks_imageload.c/.h`, `process_table.c` | DLL load → event with path + sig status. Unsigned flagged. | L |
| P2-T3 | KAPC injection on ntdll load. Resolve LdrLoadDll, queue APC to load sentinel-hook.dll. Exclusion list. | `kapc_inject.c/.h` | New process has sentinel-hook.dll loaded. Excluded processes skipped. | XL |
| P2-T4 | Registry callback (CmRegisterCallbackEx). Noise filtering. | `callbacks_registry.c/.h` | Run key → event. Explorer chatter filtered. No perf hit. | L |

---

## Phase 3: Function-Hooking DLL

**Goal:** Userland hooking DLL for ntdll API telemetry. **Book:** Ch. 2.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P3-T1 | DLL skeleton + custom hook engine (JMP patch + trampoline). | `main.c`, `hook_engine.c/.h` | LoadLibrary → hooks installed. Trampoline works. | L |
| P3-T2 | Core hooks: NtAlloc/NtProtect/NtWrite/NtCreateThread/NtMapView/NtQueueApc. Params + calling module logged. | `hooks_memory.c`, `hooks_thread.c`, `hooks_section.c` | AllocEx+WriteMem+CreateRemoteThread → 3 events with correct params. | L |
| P3-T3 | Remaining hooks (6 functions) + stack hash. | `hooks_process.c`, `hooks_section.c` | All 12 emit events. Stack hash deterministic per call path. | M |
| P3-T4 | Named pipe client. Ring buffer (1000). Reconnect. | `pipe_client.c/.h` | Events buffered if agent late. Drain on connect. No crash if pipe absent. | M |

---

## Phase 4: Agent Service — Core

**Goal:** Telemetry aggregation + detection rule engine. **Book:** Ch. 1.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P4-T1 | Windows service. Filter port client + pipe server. Event pipeline (receivers → queue → processor). | `main.cpp`, `service.cpp`, `pipeline.cpp/.h` | sc start works. Both sources feed queue. | L |
| P4-T2 | Event processing: deserialize, enrich (process table), JSON-lines log (100MB rotation). | `event_processor.cpp`, `process_table.cpp`, `json_writer.cpp` | Events in log with correct enrichment. Rotation works. | M |
| P4-T3 | Single-event rule engine. YAML parsing. Conditions: equals/contains/regex/gt. Actions: LOG/BLOCK. | `rules/rule_engine.cpp`, `rule_parser.cpp`, `rule_types.h` | "cmd.exe child of excel.exe" rule fires correctly. | L |
| P4-T4 | Sequence rules. Per-PID sliding window state machine. | `rules/sequence_engine.cpp` | Alloc→Protect(RX)→Thread chain fires. Expired partials discarded. | XL |
| P4-T5 | Threshold rules. Sliding window count. | `rules/threshold_engine.cpp` | Rapid lsass handle opens → alert. Slow → no alert. | M |

---

## Phase 5: Filesystem Minifilter

**Goal:** File I/O monitoring, scanning triggers, named pipes. **Book:** Ch. 6.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P5-T1 | Minifilter registration. Anti-Virus altitude. Pre/post-op for CREATE/WRITE/SET_INFO. Path exclusions. | `minifilter.c/.h` | fltmc shows correct altitude. Events for non-excluded paths. System dirs excluded. | L |
| P5-T2 | Async SHA-256 hash (work item queue). File event emission. 50MB cap. | `file_hash.c/.h` | .exe drop → event + correct hash. >50MB → "skipped". No I/O latency. | L |
| P5-T3 | Named pipe monitoring (IRP_MJ_CREATE_NAMED_PIPE). Suspicious pipe list. | `minifilter_pipes.c` | CS default pipe → alert. Normal pipe → low-priority. | M |
| P5-T4 | 3–5 YARA rules: XLL shellcode, UPX, CS beacon, Mimikatz. | `yara-rules/*.yar` | Compile clean. Match known-bad samples. | S |

---

## Phase 6: Network Filter (WFP Callout)

**Goal:** Network monitoring for C2 + lateral movement. **Book:** Ch. 7.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P6-T1 | WFP callout registration. Outbound + inbound ALE layers. | `wfp_callout.c/.h` | Registered in netsh. No network disruption. | L |
| P6-T2 | Classify callback: IP/port/protocol/PID/direction. Rate limit 100/s per PID. | `wfp_classify.c` | Browser → events. Rate limiting works. | M |
| P6-T3 | Agent connection table: PID, remote IP/port, counts, timestamps. CLI exposure. | `network_table.cpp/.h` | `sentinel-cli connections` shows correct table. | M |

---

## Phase 7: ETW Consumer & AMSI Provider

**Goal:** Script-level + .NET telemetry. **Book:** Ch. 8, 10.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P7-T1 | ETW framework + DotNETRuntime provider. | `etw/etw_consumer.cpp/.h`, `provider_dotnet.cpp` | Seatbelt → events with assembly/class names. | L |
| P7-T2 | Providers: PowerShell, DNS-Client, Kerberos, Services. | `provider_powershell/dns/kerberos/services.cpp` | Each generates parsed events for its scenario. | L |
| P7-T3 | Providers: AMSI, RPC, Kernel-Process (cross-validation). | `provider_amsi/rpc/kernelprocess.cpp` | AMSI events for PS. RPC for remote. K-Process correlates with driver. | M |
| P7-T4 | Custom AMSI provider (COM). YARA + string sigs on AmsiScanBuffer. | `amsi/amsi_provider.cpp/.h`, `amsi_register.cpp` | Invoke-Mimikatz → detection. Benign → clean. | XL |

---

## Phase 8: Scanner Engine & Memory Scanning

**Goal:** File + memory scanning with YARA. **Book:** Ch. 9.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P8-T1 | libyara static integration. scan_file + scan_buffer APIs. Hot-reload. | `scanner/yara_scanner.cpp/.h` | Rules match test samples. Hot-reload works. | M |
| P8-T2 | On-access scanning (minifilter trigger). Scan cache. | `scanner/onaccess_scanner.cpp` | YARA match → alert <2s. Cache hit on re-drop. | M |
| P8-T3 | Memory scanner. Unbacked executable region detection. | `scanner/memory_scanner.cpp` | RWX→RX + YARA pattern → detected. Image-backed → clean. | L |

---

## Phase 9: CLI & Operational Interface

**Goal:** CLI, config, Git-based signature updates. **Book:** Ch. 1.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P9-T1 | Core CLI: status, alerts, scan, rules reload. Command pipe. | `sentinel-cli/main.cpp`, `commands/*.cpp`, `sentinel-agent/cmd_handler.cpp` | All subcommands work. rules reload picks up new YAML. | M |
| P9-T2 | Inspection: connections, processes, hooks. --json flag. | `commands/connections/processes/hooks.cpp` | Correct data. JSON output works. | M |
| P9-T3 | Config file (TOML/INI). Sensor flags, exclusions, repo URLs. | `config.cpp/.h`, `sentinel.conf` | Disabled sensor → no telemetry. Repo URLs parse. | M |
| P9-T4 | `rules update`: git pull + validate + hot-reload. Rollback on failure. --init for clone. | `commands/rules_update.cpp`, `rules/rule_validator.cpp` | New rule → active <10s. Bad rule → rollback. --init clones. | M |
| P9-T5 | SIEM output writer. HTTP POST client for NDJSON batches to configurable endpoint. API key auth via `X-API-Key` header. Batch accumulation with size + time flush triggers. Spill-to-disk on SIEM unavailability. Drain on reconnect. Config in `[output.siem]` section. JSON serializer converts `SENTINEL_EVENT` to SentinelSIEM Appendix A envelope format. | `sentinel-agent/output/siem_writer.cpp`, `sentinel-agent/output/siem_writer.h`, `sentinel-agent/output/siem_serializer.cpp` | `enabled = true` → events arrive at SIEM endpoint as valid NDJSON. `enabled = false` → no HTTP calls. SIEM down → events spill to disk, no data loss. SIEM back → spill drains. Batch of 100 events sends as single POST. Invalid API key → logged error, events spilled. | L |
 

---

## Phase 10: Integration Testing — Ch. 13 Attack Chain

**Goal:** Full system validation against the book's case study. **Book:** Ch. 13.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P10-T1 | Test XLL payload (Ch. 13 Listing 13-1). Benign shellcode. | `tests/payloads/test_xll.cpp` | Compiles. Executes in Excel. | M |
| P10-T2 | Attack chain automation: 8 phases, validate alerts per phase. | `tests/integration/attack_chain.ps1` | End-to-end. ≥1 alert per phase. Summary report. | L |
| P10-T3 | Detection rules for all 8 attack phases. | `rules/ch13_attack_chain.yaml` | Rules fire during P10-T2. No FPs in 30min baseline. | M |
| P10-T4 | Test report: sensor coverage + known evasion vulnerabilities. | `docs/test_report.md` | All 8 phases covered. ≥1 evasion per sensor. | M |

---

## Phase 11: Hardening & Self-Protection

**Goal:** Tamper detection + evasion resistance ("Advanced" tier). **Book:** Ch. 2–12 evasions, Ch. 1 bypass classifications.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|-------------------|------|
| P11-T1 | Direct syscall + ntdll remap detection. Return address validation. | `sentinel-hook/evasion_detect.c` | SysWhispers → alert. ntdll remap → alert. | L |
| P11-T2 | Hook integrity monitoring (5s interval). Re-install on removal. | `sentinel-hook/hook_integrity.c` | Overwrite → tamper alert. Hooks restored <5s. | M |
| P11-T3 | Kernel callback tamper detection. ETW trace session monitoring. | `sentinel-drv/self_protect.c/.h` | Callback removal → alert. Trace stop → alert. | XL |
| P11-T4 | AMSI bypass detection. AmsiScanBuffer integrity check. | `sentinel-agent/amsi/amsi_integrity.cpp` | Standard bypass → tamper alert. | M |
| P11-T5 | Telemetry cross-validation (driver vs. ETW Kernel-Process). | `sentinel-agent/crossvalidation.cpp` | Simulated callback disable → cross-val alert. | M |

---

## Phase Summary & Dependency Map

| Phase | Name | Tasks | Depends On | Book Ch. | Tier |
|-------|------|-------|------------|----------|------|
| P0 | Project Scaffolding | 5 | — | Ch. 1 | Foundation |
| P1 | Process/Thread Callbacks | 4 | P0 | Ch. 3 | Basic |
| P2 | Object/Image/Registry | 4 | P1 | Ch. 4–5 | Basic |
| P3 | Function-Hooking DLL | 4 | P2 (KAPC) | Ch. 2 | Basic |
| P4 | Agent Service Core | 5 | P1, P3 | Ch. 1 | Basic |
| P5 | Filesystem Minifilter | 4 | P4 | Ch. 6 | Intermediate |
| P6 | Network Filter (WFP) | 3 | P4 | Ch. 7 | Intermediate |
| P7 | ETW & AMSI | 4 | P4 | Ch. 8, 10 | Intermediate |
| P8 | Scanner Engine | 3 | P4, P5 | Ch. 9 | Intermediate |
| P9 | CLI & Config | 4 | P4–P8 | Ch. 1 | Intermediate |
| P10 | Integration Testing | 4 | All | Ch. 13 | Validation |
| P11 | Hardening | 5 | All | Ch. 2–12 | Advanced |

**Total: 49 tasks, 12 phases. Estimated 36–52 Claude Code sessions.**

---

## Code Conventions & Constraints

### Kernel-Mode (sentinel-drv)
- C17. No C++, no STL, no exceptions. Pool tag `'SnPc'`. `ExAllocatePool2`. Document IRQL. Check every NTSTATUS. Clean DriverUnload. Pass Driver Verifier.

### User-Mode (sentinel-hook, sentinel-agent, sentinel-cli)
- sentinel-hook: C17, minimal CRT. sentinel-agent: C++20/MSVC. sentinel-cli: C++20, no Boost.
- No external network calls (local-only v1). Thread pool for async. Overlapped pipe I/O. JSON logging.

### Detection Rules (YAML)
- Grouped by ATT&CK tactic. Fields reference `telemetry.h`. Severity: informational/low/medium/high/critical. Actions: LOG/BLOCK/DECEIVE.

---

## v2 Roadmap: Remote Management & Multi-Host

v1 is intentionally local-only. v2 introduces remote management (install on test machine, monitor from admin workstation).

### sentinel-server (new, admin machine)
- TLS listener for agent connections. SQLite storage (or ELK/Splunk forwarding). REST API for alerts/telemetry/connections. Agent enrollment + heartbeat. Optional web dashboard.

### Agent/CLI Changes
- Agent: configurable output mode (local/remote/both). TLS push + heartbeat. Local fallback on disconnect.
- Signature updates shift to server-push; git pull remains as standalone fallback.
- CLI: `--remote <server:port>` flag. All commands work identically in remote mode.

### Design Constraints
- Server in C++ (same toolchain). TLS only. Multi-agent. No cloud deps. Single binary.

### v1 Prep for v2
- `SENTINEL_EVENT` + `common/ipc` serialization → TLS is just a new sink. Length-prefixed framing → maps to TCP. CLI transport layer is abstract. Pipeline decouples ingestion from output.

### Other v2+ Candidates
- ELAM + EtwTi (Ch. 11–12, requires MS cert)
- Hypervisor detection (Appendix)
- Adversary deception (Ch. 1 "Advanced")
- RPC filters (Appendix)
- Nirvana hooks (Appendix)