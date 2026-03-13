# SentinelPOC

A proof-of-concept Endpoint Detection & Response (EDR) agent for Windows x64, built from the ground up with kernel-mode telemetry, user-mode API hooking, YARA scanning, and a multi-layer detection engine.

Architecture derived from sensor models in *Evading EDR* by Matt Hand (No Starch Press, 2023).

---

## What It Does

SentinelPOC instruments a Windows system at every layer — kernel callbacks, inline API hooks, ETW tracing, AMSI integration, and file system filtering — to collect security telemetry and detect adversary techniques in real time.

**Highlights:**

- **Kernel-mode driver** with process, thread, object, image-load, registry, file I/O, network, and named pipe callbacks
- **Automatic DLL injection** via kernel APC into every new process for user-mode API hook coverage
- **13 hooked ntdll/kernel32 functions** capturing memory allocation, process injection, and thread creation
- **8 ETW providers** for .NET assembly loads, PowerShell script blocks, DNS queries, Kerberos auth, RPC calls, and more
- **Custom AMSI provider** that scans PowerShell/VBScript/JScript content against YARA rules
- **On-access YARA scanning** triggered by minifilter file events with hash-based caching
- **Three-tier detection engine**: single-event rules, time-ordered sequence rules, and threshold-based alerting
- **14 YARA rules** detecting Cobalt Strike, Mimikatz, packed binaries, suspicious PE characteristics, and XLL shellcode
- **JSON-lines telemetry logging** with automatic rotation

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL MODE                              │
│                                                                 │
│  sentinel-drv.sys                                               │
│  ├── Process/Thread callbacks ─────┐                            │
│  ├── Object callbacks (LSASS       │                            │
│  │   protection)                   │   Filter Communication     │
│  ├── Image-load + KAPC injection   ├──── Port ──────────┐       │
│  ├── Registry callbacks            │                    │       │
│  ├── Minifilter (file I/O + hash)  │                    │       │
│  ├── Named pipe monitoring         │                    │       │
│  └── WFP callout (network)  ──────┘                    │       │
└─────────────────────────────────────────────────────────│───────┘
                                                         │
┌─────────────────────────────────────────────────────────│───────┐
│                        USER MODE                        │       │
│                                                         ▼       │
│  sentinel-agent.exe                                             │
│  ├── Driver Port Receiver ◄────────────────────────────┘        │
│  ├── Pipe Server ◄──────────── sentinel-hook.dll (per-process)  │
│  ├── ETW Consumer ◄─────────── 8 system providers               │
│  ├── AMSI Provider ◄────────── PowerShell / script hosts        │
│  │                                                              │
│  ├── Event Queue ──► Processing Thread                          │
│  │                    ├── Process table enrichment               │
│  │                    ├── On-access YARA scanner                 │
│  │                    ├── Single-event rule engine               │
│  │                    ├── Sequence rule engine                   │
│  │                    ├── Threshold rule engine                  │
│  │                    └── JSON log writer                        │
│  │                                                              │
│  └── Console / Service output                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| **sentinel-drv** | C17 (WDK) | Kernel-mode WDM driver with 8 callback types, minifilter, WFP callout, and KAPC injection |
| **sentinel-hook** | C17 | User-mode hooking DLL injected via kernel APC. Inline hooks on 13 ntdll/kernel32 functions |
| **sentinel-agent** | C++20 | Windows service: event aggregation, rule engines, ETW consumer, AMSI provider, YARA scanner |
| **sentinel-amsi** | C++20 | AMSI provider DLL registered with Windows for script content scanning |
| **sentinel-cli** | C++20 | Console management tool (stub — Phase 9) |

---

## Telemetry Sources

| Source | Origin | What It Captures |
|--------|--------|------------------|
| Process | Driver callback | Process creation/termination, image path, command line, SID, integrity level |
| Thread | Driver callback | Thread creation/termination, remote thread detection |
| Object | Driver callback | Handle operations on protected processes (lsass, csrss, services) |
| ImageLoad | Driver callback | DLL/EXE loads with signature validation |
| Registry | Driver callback | Key create/open, value set/delete (noise-filtered) |
| File | Minifilter | File create/write/rename/delete with SHA-256 hash |
| Network | WFP callout | Inbound/outbound connections, rate-limited per PID |
| Pipe | Minifilter | Named pipe creation with suspicious pipe detection |
| HookDll | Inline hooks | 13 API calls: memory ops, thread ops, process open, pipe create |
| ETW | 8 providers | .NET assemblies, PowerShell scripts, DNS, Kerberos, RPC, services, kernel process |
| AMSI | COM provider | Script content scanned by PowerShell/VBScript/JScript hosts |
| Scanner | YARA engine | On-access file scan results with rule match details |

---

## Detection Capabilities

### YARA Rules (14 rules across 5 files)

| File | Rules | Detects |
|------|-------|---------|
| `cobaltstrike_beacon.yar` | 3 | Beacon config blocks, shellcode stagers, default pipe names |
| `mimikatz.yar` | 3 | Binary builds, PowerShell ports (Invoke-Mimikatz), kernel driver (mimidrv) |
| `suspicious_pe.yar` | 4 | RWX sections, injection imports, packer section names, high-entropy sections |
| `upx_packed.yar` | 2 | Standard and modified UPX packing |
| `xll_shellcode.yar` | 2 | Excel XLL add-ins with shellcode stagers or injection imports |

### Behavioral Detection Rules (5 rules, 3 types)

| Rule | Type | ATT&CK | Trigger |
|------|------|--------|---------|
| Suspicious RWX Allocation | Single | T1055 | Cross-process `NtAllocateVirtualMemory` with `PAGE_EXECUTE_READWRITE` |
| Remote Thread Creation | Single | T1055.003 | `NtCreateThreadEx` targeting a different process |
| Excel Spawns cmd.exe | Single | T1059.003 | `cmd.exe` child process of `excel.exe` |
| Shellcode Runner Pattern | Sequence | T1055 | Alloc(RW) → Protect(RX) → CreateThread within 5 seconds |
| Rapid Memory Allocation | Threshold | — | ≥500 `NtAllocateVirtualMemory` calls in 10 seconds from one process |

---

## Hooked Functions

The hooking DLL intercepts 13 ntdll/kernel32 functions via inline hooks:

| Category | Functions |
|----------|-----------|
| **Memory** | `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtCreateSection` |
| **Thread** | `NtCreateThreadEx`, `NtQueueApcThread`, `NtSuspendThread`, `NtResumeThread` |
| **Process** | `NtOpenProcess` |
| **Pipe** | `NtCreateNamedPipeFile` |

---

## Building

### Prerequisites

- **Visual Studio 2022** with the C++ desktop development workload
- **CMake 3.20+**
- **Windows Driver Kit (WDK)** — required for the kernel driver; user-mode components build without it

### Configure & Build

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

If WDK is not installed, `sentinel-drv` is skipped automatically. All other components build normally.

Output binaries land in `build/bin/Release/`:
- `sentinel-agent.exe` — the main agent service
- `sentinel-drv.sys` — kernel driver (requires WDK)
- `sentinel-hook.dll` — hooking DLL (injected by driver)
- `sentinel-amsi.dll` — AMSI provider (registered by agent)

### Test Signing (required for driver deployment)

```powershell
# Enable test signing on the VM (requires reboot)
.\scripts\setup-testsigning.ps1

# Sign the driver
.\scripts\sign-driver.ps1
```

> **Warning:** Only enable test signing on isolated test VMs. Never on production systems.

---

## Deployment

### 1. Prepare the deployment directory

```powershell
# Create the deployment directory
New-Item -ItemType Directory -Force -Path C:\SentinelPOC

# Copy binaries
Copy-Item build\bin\Release\sentinel-agent.exe C:\SentinelPOC\
Copy-Item build\bin\Release\sentinel-hook.dll  C:\SentinelPOC\
Copy-Item build\bin\Release\sentinel-amsi.dll  C:\SentinelPOC\

# Copy rules
Copy-Item -Recurse rules\       C:\SentinelPOC\rules\
Copy-Item -Recurse yara-rules\  C:\SentinelPOC\yara-rules\
```

### 2. Install and start the kernel driver

```powershell
# Copy the signed driver
Copy-Item build\bin\Release\sentinel-drv.sys C:\SentinelPOC\

# Create the driver service
sc.exe create SentinelDrv type=kernel binPath="C:\SentinelPOC\sentinel-drv.sys"

# Start the driver
sc.exe start SentinelDrv
```

### 3. Run the agent

**Console mode** (recommended for testing):

```powershell
# Run from an elevated command prompt
C:\SentinelPOC\sentinel-agent.exe
```

The agent will:
1. Load YAML detection rules from `C:\SentinelPOC\rules\`
2. Compile YARA rules from `C:\SentinelPOC\yara-rules\`
3. Connect to the kernel driver's filter communication port
4. Start the named pipe server for hook DLL telemetry
5. Initialize ETW consumers for 8 system providers
6. Register the custom AMSI provider
7. Begin processing events and writing to the JSON log

Press **Ctrl+C** to stop cleanly.

**Service mode** (for persistent deployment):

```powershell
sc.exe create SentinelAgent binPath="C:\SentinelPOC\sentinel-agent.exe" start=auto
sc.exe start SentinelAgent
```

### 4. Verify operation

With the agent running, you should see:
- Startup messages confirming rule loading and component initialization
- Scanner alerts when malicious files are written to disk
- Rule engine alerts when suspicious behavior is detected
- All telemetry written to `C:\SentinelPOC\telemetry.jsonl`

---

## Testing On-Access Scanning

To verify YARA on-access scanning is working:

```cmd
:: From an elevated cmd.exe (not PowerShell — AMSI will block the strings)
echo sekurlsa:: kerberos:: lsadump:: privilege:: logonPasswords > C:\Users\%USERNAME%\Desktop\evil.txt
```

Within a few seconds the agent console should display:

```
[NNN] source=Scanner type=OnAccess path=C:\Users\...\evil.txt match=YES rule=Mimikatz_Binary
```

The minifilter detects the file creation, computes a SHA-256 hash, and the on-access scanner runs YARA rules against the file. Results are cached for 5 minutes to avoid redundant rescans.

---

## Project Structure

```
claude-edr/
├── CMakeLists.txt              Top-level build configuration
├── common/                     Shared headers
│   ├── telemetry.h            Event schema (SENTINEL_EVENT union)
│   ├── constants.h            System-wide constants
│   ├── ipc.h                  Named pipe protocol
│   └── ipc_serialize.h        Binary serialization helpers
├── sentinel-drv/              Kernel-mode driver
│   ├── main.c                 DriverEntry, cleanup, unload
│   ├── callbacks_process.c    PsSetCreateProcessNotifyRoutineEx
│   ├── callbacks_thread.c     PsSetCreateThreadNotifyRoutineEx
│   ├── callbacks_object.c     ObRegisterCallbacks
│   ├── callbacks_image.c      PsSetLoadImageNotifyRoutineEx
│   ├── callbacks_registry.c   CmRegisterCallbackEx
│   ├── minifilter.c           FltRegisterFilter (file I/O)
│   ├── minifilter_pipes.c     Named pipe creation monitoring
│   ├── wfp_callout.c          WFP network callout
│   ├── kapc_inject.c          Kernel APC DLL injection
│   └── file_hash.c            SHA-256 file hashing
├── sentinel-hook/             User-mode hooking DLL
│   ├── main.c                 DllMain, hook installation
│   ├── hook_engine.c          Inline hook framework
│   ├── hooks_memory.c         Memory operation hooks
│   ├── hooks_thread.c         Thread operation hooks
│   ├── hooks_process.c        Process operation hooks
│   └── pipe_client.c          Named pipe telemetry sender
├── sentinel-agent/            Agent service
│   ├── main.cpp               Entry point
│   ├── service.cpp            SCM handler + console mode
│   ├── pipeline.cpp           Event queue + receiver threads
│   ├── event_processor.cpp    Event routing + enrichment
│   ├── json_writer.cpp        JSON-lines log output
│   ├── network_table.cpp      Connection tracking table
│   ├── scanner/
│   │   ├── yara_scanner.cpp   libyara integration
│   │   └── onaccess_scanner.cpp  File event → YARA scan
│   ├── rules/
│   │   ├── rule_engine.cpp    Single-event rule evaluation
│   │   ├── sequence_engine.cpp  Time-ordered sequence detection
│   │   ├── threshold_engine.cpp  Count-based alerting
│   │   └── rule_parser.cpp    YAML rule loading
│   ├── etw/
│   │   └── etw_consumer.cpp   ETW trace session + 8 providers
│   └── amsi/
│       └── amsi_provider.cpp  Custom AMSI COM provider
├── sentinel-amsi/             AMSI provider DLL host
├── sentinel-cli/              CLI tool (stub)
├── yara-rules/                YARA detection rules (14 rules)
├── rules/                     YAML behavioral rules (5 rules)
├── tests/                     Integration tests
├── scripts/                   Setup and signing scripts
├── deps/                      External dependencies (libyara)
├── cmake/                     CMake modules (FindWdk)
└── certs/                     Test signing certificates
```

---

## Implementation Phases

| Phase | Description | Status |
|-------|-------------|--------|
| P0 | Project scaffolding, build system, shared headers | ✅ Complete |
| P1 | Process and thread kernel callbacks | ✅ Complete |
| P2 | Object, image-load, and registry callbacks + KAPC injection | ✅ Complete |
| P3 | User-mode hooking DLL with 13 inline hooks | ✅ Complete |
| P4 | Agent service with event pipeline and 3-tier rule engine | ✅ Complete |
| P5 | Minifilter, file hashing, and named pipe monitoring | ✅ Complete |
| P6 | WFP network callout and connection table | ✅ Complete |
| P7 | ETW consumer (8 providers) and custom AMSI provider | ✅ Complete |
| P8 | YARA scanner integration and on-access file scanning | ✅ Complete |
| P9 | CLI management tool | 🔲 Pending |
| P10 | Integration testing (end-to-end attack chain) | 🔲 Pending |
| P11 | Hardening and self-protection (evasion detection) | 🔲 Pending |

See `REQUIREMENTS.md` for the full implementation roadmap.

---

## License

MIT License. See [LICENSE](LICENSE).

## Disclaimer

This is an educational proof-of-concept built for learning and research purposes. It is **not** production security software. Deploy only in authorized, isolated test environments.

## Acknowledgments

- *Evading EDR* by Matt Hand (No Starch Press, 2023) — the architectural reference for this project
- [YARA](https://virustotal.github.io/yara/) — pattern matching engine
- [MITRE ATT&CK](https://attack.mitre.org/) — technique references for detection rules
