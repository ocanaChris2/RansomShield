# RansomShield

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/J1R621M7VN)

A Windows kernel-mode minifilter driver that detects and blocks ransomware in real time, paired with a user-mode control client and a background tray agent that shows live Windows notifications when a process is blocked.

> **Certification:** an enterprise-grade security & quality certification package for the driver lives in [`certification/`](certification/) — formal report, threat model, compliance matrix, and reproducible static/runtime quality gates (Code Analysis, CodeQL, BinSkim, SDV/DVL, Driver Verifier, signed-catalog packaging). CI runs the host-runnable gates on every pull request and publishes test releases from version tags (see [CI and releases](#ci-and-releases)). Start with the [certification report](certification/RansomShield-Certification-Report.md).

## How it works

RansomShield registers with the Windows Filter Manager (FltMgr) at altitude **325010** (Anti-Virus range) and watches two I/O operation types:

| IRP | Direction | Purpose |
|-----|-----------|---------|
| `IRP_MJ_WRITE` | pre-op | Catches file overwrites / in-place encryption |
| `IRP_MJ_SET_INFORMATION` | pre + post | Catches extension renames and deletes |

A **per-PID heuristic engine** tracks every file operation using a sliding time window. When a process exceeds the threshold (default: **50 ops in 10 seconds**), the driver:

1. Marks the PID as blocked. The block is sticky: it lasts until an administrator unblocks the process or the process exits.
2. Returns `STATUS_ACCESS_DENIED` for all subsequent write/rename/delete IRPs from that PID.
3. Pushes a `RsNotifyBlockedPid` notification to the user-mode client via the FltMgr communication port.

Tracking stays bounded: a process's context is freed when the process exits, and at most 1,024 processes are tracked at once.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Mode                                │
│                                                                 │
│  RansomShieldTray.exe  (background, no console)                 │
│  ├─ TrayMain.cpp         WinMain, message loop, reconnect timer │
│  ├─ NotificationManager  Shell_NotifyIcon + balloon tips        │
│  ├─ CommManager          FilterConnect/Send/Get                 │
│  ├─ ConfigManager        registry persistence                   │
│  └─ EventLogger          Windows Event Log + file log           │
│                                                                 │
│  RansomShieldClient.exe  (CLI / one-shot commands)              │
│  ├─ Main.cpp             argument dispatch, daemon loop         │
│  └─  ↑ shares CommManager, ConfigManager, EventLogger           │
│                                                                 │
│         FilterSendMessage / FilterGetMessage                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │  \RansomShieldPort  (1 client max)
┌──────────────────────────────▼──────────────────────────────────┐
│                       Kernel Mode                               │
│                                                                 │
│  RansomShield.sys  (minifilter @ alt 325010)                    │
│  ├─ RansomShield.c   DriverEntry, callbacks                     │
│  ├─ RsContext.c      per-PID hash table, allowlist              │
│  └─ RsCommPort.c     FltMgr port dispatch                       │
└─────────────────────────────────────────────────────────────────┘
```

> **One connection at a time.** While `RansomShieldTray.exe` is running it holds the only allowed connection to `\RansomShieldPort`. Stop the tray agent before using CLI commands that also connect to the driver.

### Heuristic engine (`RsContext.c`)

```c
// Per-PID tracking context, allocated from non-paged, no-execute pool
typedef struct _RS_PROCESS_CONTEXT {
    LIST_ENTRY          Link;              // chained in a 1021-bucket hash table
    LIST_ENTRY          LruLink;           // LRU list, least recently active first
    ULONG               ProcessId;
    WCHAR               ImageName[RS_MAX_IMAGE_NAME_LEN];       // 260 WCHARs, non-paged copy

    // Ring buffer of operation timestamps (KeQueryInterruptTime, 100 ns ticks)
    RS_OPERATION_ENTRY  Operations[RS_MAX_OPERATIONS_PER_PID];  // 256 entries
    ULONG               OperationHead;     // next write position
    ULONG               OperationCount;    // valid entries

    BOOLEAN             IsBlocked;         // sticky until unblocked or the process exits
    LONGLONG            BlockedTimestamp;
    LONGLONG            LastActivityTime;
} RS_PROCESS_CONTEXT, *PRS_PROCESS_CONTEXT;
```

- Hash table: 1021 prime buckets, separate chaining via `LIST_ENTRY`, all in `NonPagedPoolNx`.
- One spinlock (`g_ContextLock`) guards the table and keeps critical sections short. The dynamic allowlist has its own push lock (`g_AllowlistLock`), so comparing image names, which reads paged memory, never happens at `DISPATCH_LEVEL`.
- New entries use double-checked locking: allocate at `PASSIVE_LEVEL`, re-acquire lock, re-check, insert or free the loser.
- Blocked state is **sticky**: it does not expire when activity drops. It ends when an administrator sends `RsRequestUnblockPid` or when the process exits, so a later process that reuses the PID starts clean.
- Process exit: a `PsSetCreateProcessNotifyRoutineEx` callback frees a process's context when the process exits. That API requires the `/INTEGRITYCHECK` linker flag, so the driver must be signed to load (a test signature is enough). If the callback cannot be registered, the driver still loads and relies on the cap.
- Cap: at most `RS_MAX_TRACKED_PIDS` (1,024) contexts. When the table is full, the least recently active context that is not blocked is evicted. If every tracked process is blocked, the new process is not tracked (fail open, the same policy as an allocation failure).

### Communication port (`RsCommPort.c`)

The kernel exposes `\RansomShieldPort` (admin-only ACL, one client at a time).

```
Kernel ──FltSendMessage──► User    (push alert after releasing spinlock)
User   ──FilterSendMessage──► Kernel  (queries, commands, config)
User   ──FilterGetMessage──► Kernel  (blocking receive loop in CommManager thread)
```

- Each request is copied into kernel memory before it is checked, so user mode cannot change it halfway through. Replies are built in a kernel buffer and copied out at the end. User buffers are touched only inside `__try/__except`, never while holding a lock.
- Clients can reconnect, for example after the driver is reloaded: the driver closes the old connection when the client disconnects, and `CommManager` restarts its listener thread, so alerts keep arriving.

### Protocol (`SharedDefs.h`)

Every message starts with a common header:

```c
typedef struct _RS_MESSAGE_HEADER {
    RS_MESSAGE_TYPE  MessageType;      // see enum below
    ULONG            MessageSize;      // total bytes including this header
    ULONG            SequenceNumber;   // monotonically increasing
    ULONG            ProtocolVersion;  // current: 2
} RS_MESSAGE_HEADER;
```

Message type ranges:

| Range | Direction | Purpose |
|-------|-----------|---------|
| 1 – 99 | Kernel → User | Unsolicited notifications (`RsNotifyBlockedPid`, …) |
| 100 – 199 | User → Kernel | Queries (`RsQueryBlockedPids`, `RsQueryConfig`, …) |
| 200 – 299 | User → Kernel | Commands (`RsRequestUnblockPid`, `RsRequestPause`, …) |
| 300 – 399 | User → Kernel | Configuration (`RsUpdateConfig`, `RsUpdateAllowlistChunk`, …) |

Blocked-PID notification sent by the kernel:

```c
typedef struct _RS_NOTIFICATION_BLOCKED_PID {
    RS_MESSAGE_HEADER  Header;           // MessageType = RsNotifyBlockedPid (1)
    ULONG              ProcessId;
    WCHAR              ImageName[260];
    LONGLONG           BlockedTimestamp; // 100 ns ticks since boot
    ULONG              OperationCount;   // ops that triggered the block
} RS_NOTIFICATION_BLOCKED_PID;
```

---

## Build

**Prerequisites:** Visual Studio 2026 (version 18, v145 toolset), `nuget.exe` in repo root. WDK headers and libs come from NuGet — no separate WDK install required.

```powershell
# 1. Restore WDK NuGet packages (one-time)
.\nuget.exe restore RansomShield.sln -PackagesDirectory packages

# 2. Build all three projects (Debug x64)
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild RansomShield.sln /p:Configuration=Debug /p:Platform=x64

# Outputs:
#   x64\Debug\RansomShield.sys          ← kernel driver
#   x64\Debug\RansomShieldClient.exe    ← CLI control client
#   x64\Debug\RansomShieldTray.exe      ← background tray agent
```

NuGet packages used:

| Package | Provides |
|---------|----------|
| `Microsoft.Windows.WDK.x64` | kernel-mode headers (`km/`, `shared/`) and libs (`fltMgr.lib`, `ntoskrnl.lib`, …) |
| `Microsoft.Windows.SDK.CPP` | shared headers (`ntstatus.h`, `fltUserStructures.h`, …) |
| `Microsoft.Windows.SDK.CPP.x64` | user-mode x64 libs (`fltLib.lib`, `advapi32.lib`, …) |

---

## Build Manual

This section covers building each component individually, explains what the build system does internally, and documents every known error with its fix.

### Prerequisites checklist

Before building anything, verify:

| Requirement | How to check | Where to get it |
|-------------|-------------|-----------------|
| Visual Studio 2026 (version 18) with the **Desktop development with C++** workload | `vswhere -latest -property installationVersion` (expect `18.x`) | [visualstudio.microsoft.com](https://visualstudio.microsoft.com) |
| MSVC **v145** toolset installed | VS Installer → Individual components → "MSVC v145" | VS Installer |
| `nuget.exe` present in repo root | `Test-Path .\nuget.exe` | [nuget.org/downloads](https://www.nuget.org/downloads) |
| Running as **Administrator** | `[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')` | Right-click PowerShell → Run as administrator |

> **No WDK install needed.** All kernel headers and libs come from NuGet packages. The `packages.config` pins exact versions (`10.0.26100.6584`) so the build is fully self-contained.

---

### Step 1 — Restore NuGet packages (one-time)

```powershell
.\nuget.exe restore RansomShield.sln -PackagesDirectory packages
```

This downloads and extracts three packages under `packages\`:

```
packages\
  Microsoft.Windows.SDK.CPP.10.0.26100.6584\       ← shared + user-mode headers
  Microsoft.Windows.SDK.CPP.x64.10.0.26100.6584\   ← user-mode x64 libs
  Microsoft.Windows.WDK.x64.10.0.26100.6584\        ← kernel-mode headers + libs
```

Both `.vcxproj` files import `.props` files from these directories **before** `Microsoft.Cpp.Default.props`. If the packages are missing, MSBuild silently skips those imports and the include / lib paths are never set, causing every subsequent compile error below.

**Troubleshooting — NuGet restore failures:**

| Error | Cause | Fix |
|-------|-------|-----|
| `nuget.exe` is not recognized | `nuget.exe` missing from repo root | Download `nuget.exe` (CLI v6) from nuget.org and place it in the repo root |
| `Unable to find version '10.0.26100.6584'` | NuGet feed unavailable or version retired | Check internet connection; if the version is genuinely retired, update `packages.config` and both `.vcxproj` imports to the nearest available version |
| `packages\` directory not created | Restore ran but output dir was wrong | Always pass `-PackagesDirectory packages` — without it NuGet uses a global cache and the `.vcxproj` relative paths break |
| SSL/TLS error on restore | Corporate proxy or outdated .NET | Run `nuget.exe update -self` first, or add `-ForceEnglishOutput` and check the proxy settings |

---

### Step 2 — Build the kernel driver (`RansomShield.sys`)

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"

# Debug (symbols, no optimization)
& $msbuild RansomShield.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir="$PWD\" /v:minimal /nologo

# Release (MaxSpeed, COMDAT folding; the PDB is kept for analysis, not shipped)
& $msbuild RansomShield.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$PWD\" /v:minimal /nologo
```

**Output:** `x64\Debug\RansomShield.sys` or `x64\Release\RansomShield.sys`

#### What the driver project does internally

The driver is built as `ConfigurationType=DynamicLibrary` (not the WDK "Driver" type, which requires the installed WDK VS extension). The `.vcxproj` applies the following non-default flags to make a valid kernel binary:

| Flag | Value | Why |
|------|-------|-----|
| `TargetExt` | `.sys` | Renames the output from `.dll` to `.sys` |
| `SubSystem` | `Native` | Kernel drivers run in the native subsystem |
| `Driver` | `WDM` | Adds `/DRIVER:WDM` linker flag |
| `EntryPointSymbol` | `GsDriverEntry` | Security-cookie wrapper that calls `DriverEntry` |
| `IgnoreAllDefaultLibraries` | `true` | Excludes all user-mode CRT libs |
| `/kernel` | compiler flag | Enables kernel-mode code generation |
| `BufferSecurityCheck` | `true` (`/GS`) | Stack cookies, as in WDK driver projects; the kernel-mode support comes from `BufferOverflowK.lib` |
| `ControlFlowGuard` | `Guard` (`/guard:cf`, compiler and linker) | Control Flow Guard, as in WDK driver projects |
| `ExceptionHandling` | `false` | No C++ SEH in kernel mode |
| `RuntimeLibrary` | `MultiThreaded` | Static, no CRT DLL reference |
| Linked libs | `ntoskrnl.lib fltMgr.lib BufferOverflowK.lib hal.lib wdmsec.lib` | All from WDK NuGet package |
| `/INTEGRITYCHECK` | linker flag | Required by `PsSetCreateProcessNotifyRoutineEx` (process-exit tracking). The driver must then be signed to load; a test signature is enough |
| `GenerateDebugInformation` | `true`, Release included | BinSkim reads the compiler options from the PDB; `/PDBALTPATH:%_PDB%` keeps the build path out of the driver |

**Troubleshooting — driver build errors:**

| Error message | Cause | Fix |
|---------------|-------|-----|
| `MSBuild.exe not found at C:\Program Files\Microsoft Visual Studio\18\...` | VS installed at a different path, or edition differs (Enterprise/Professional vs Community) | Find the correct path: `& "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe` and substitute it in the command |
| `The imported project ... packages\Microsoft.Windows.WDK.x64...\build\native\...props" was not found` | NuGet packages not restored | Run `.\nuget.exe restore RansomShield.sln -PackagesDirectory packages` first |
| `error MSB8020: The build tools for v145 (Platform Toolset = 'v145') cannot be found` | MSVC v145 toolset not installed | Open VS Installer → Modify → Individual components → search "MSVC v145" → install |
| `fatal error C1083: Cannot open include file: 'fltkernel.h'` | WDK NuGet package not restored or `SolutionDir` not passed | Restore packages and always pass `/p:SolutionDir="$PWD\"` — without it `$(SolutionDir)` is empty and the include paths resolve incorrectly |
| `fatal error C1083: Cannot open include file: 'ntstatus.h'` | SDK.CPP package missing | Same as above; `ntstatus.h` comes from `Microsoft.Windows.SDK.CPP` |
| `error LNK2019: unresolved external symbol __imp_FltRegisterFilter` | `fltMgr.lib` not linked | Usually caused by missing NuGet packages or incorrect `$(WdkKmLibs)` path; re-restore packages |
| `error LNK2019: unresolved external symbol __security_cookie` | `BufferOverflowK.lib` missing | Same root cause — re-restore WDK package |
| `error LNK2001: unresolved external symbol mainCRTStartup` | Linker using wrong entry point | Ensure `EntryPointSymbol=GsDriverEntry` and `IgnoreAllDefaultLibraries=true` are both set in the `.vcxproj`; do not open the project in Visual Studio and let it "fix" settings |
| `warning LNK4210: .CRT section exists` | CRT initializers present | A source file included a CRT header (`<stdio.h>`, `<stdlib.h>`, etc.). Remove it — kernel code must not use the CRT |
| `error C2220: warning treated as error` | `TreatWarningAsError=true` | The project currently sets `false`; if you enabled it, fix the underlying warning |
| `LINK : fatal error LNK1281: Unable to generate IMPLIB` | Side-effect of `DynamicLibrary` config type | Normal — the `.exp`/`.lib` are created but unused; ignore them |

---

### Step 3 — Build the user-mode client (`RansomShieldClient.exe`)



```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"

# Debug
& $msbuild RansomShieldClient.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir="$PWD\" /v:minimal /nologo

# Release
& $msbuild RansomShieldClient.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$PWD\" /v:minimal /nologo
```

**Output:** `x64\Debug\RansomShieldClient.exe` or `x64\Release\RansomShieldClient.exe`

#### What the client project does internally

The client is a standard C++17 console application (`ConfigurationType=Application`) linked against user-mode FltMgr APIs:

| Setting | Value |
|---------|-------|
| Language standard | C++17 (`stdcpp17`) |
| Include paths | `$(TargetPlatformSdkRootOverride)\Include\10.0.26100.0\um`, `...\shared`, `...\ucrt` (all from NuGet) |
| Linked libs | `fltLib.lib advapi32.lib kernel32.lib` (user-mode x64 from `Microsoft.Windows.SDK.CPP.x64`) |
| Lib paths | `$(winsdk_cpp_x64_root)\um\x64` and `...\ucrt\x64` |

**Troubleshooting — client build errors:**

| Error message | Cause | Fix |
|---------------|-------|-----|
| `fatal error C1083: Cannot open include file: 'FltUser.h'` | SDK.CPP NuGet package not restored or `SolutionDir` not passed | `.\nuget.exe restore RansomShield.sln -PackagesDirectory packages` then pass `/p:SolutionDir="$PWD\"` |
| `fatal error C1083: Cannot open include file: 'windows.h'` | Same root cause — `Windows.h` is in the SDK.CPP `um` include path | Re-restore packages |
| `error LNK2019: unresolved external symbol FilterConnectCommunicationPort` | `fltLib.lib` not found | `$(winsdk_cpp_x64_root)` is empty, meaning `Microsoft.Windows.SDK.CPP.x64` was not restored correctly |
| `error LNK2019: unresolved external symbol RegOpenKeyExW` | `advapi32.lib` not linked | Re-restore `Microsoft.Windows.SDK.CPP.x64` |
| `error C2429: language feature 'if constexpr' requires compiler flag '/std:c++17'` | Language standard not set | Check that `<LanguageStandard>stdcpp17</LanguageStandard>` is present in both configurations inside `RansomShieldClient.vcxproj` |
| `error C2220: warning treated as error` | Unused variable or similar warning promoted | Fix the underlying warning or set `TreatWarningAsError=false` |
| Linker outputs to wrong directory | `SolutionDir` not passed, so `$(SolutionDir)` is undefined and `OutDir` resolves incorrectly | Always pass `/p:SolutionDir="$PWD\"` when building a single `.vcxproj` outside the solution |

---

### Step 4 — Build the tray agent (`RansomShieldTray.exe`)

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"

# Debug
& $msbuild RansomShieldTray.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir="$PWD\" /v:minimal /nologo

# Release
& $msbuild RansomShieldTray.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$PWD\" /v:minimal /nologo
```

**Output:** `x64\Debug\RansomShieldTray.exe` or `x64\Release\RansomShieldTray.exe`

#### What the tray project does internally

`RansomShieldTray` is a Windows-subsystem application (no console window). It reuses `CommManager`, `ConfigManager`, and `EventLogger` from the CLI client — the only new files are `TrayMain.cpp` (entry point and window procedure) and `NotificationManager.h/.cpp` (tray icon and balloon tips).

| Setting | Value |
|---------|-------|
| Subsystem | `Windows` (no console, `wWinMain` entry point) |
| Preprocessor | `_WINDOWS` instead of `_CONSOLE` |
| Extra lib | `shell32.lib` — for `Shell_NotifyIcon`, `SHGetStockIconInfo`, `ShellExecuteW` |
| Icon | System shield icon (`SIID_SHIELD`) via `SHGetStockIconInfo` |

**Troubleshooting — tray build errors:**

| Error message | Cause | Fix |
|---------------|-------|-----|
| `fatal error C1083: Cannot open include file: 'shellapi.h'` | SDK.CPP NuGet package not restored | Run `.\nuget.exe restore RansomShield.sln -PackagesDirectory packages` |
| `error LNK2019: unresolved external symbol Shell_NotifyIconW` | `shell32.lib` missing from linker deps | Confirm `shell32.lib` is listed in `<AdditionalDependencies>` in `RansomShieldTray.vcxproj` |
| `error LNK2019: unresolved external symbol _wWinMain` | Source file defines `wmain` instead of `wWinMain`, or subsystem mismatch | `TrayMain.cpp` must define `int WINAPI wWinMain(...)` and the vcxproj must have `<SubSystem>Windows</SubSystem>` |
| Application flashes a console window on launch | Project built with `SubSystem=Console` instead of `Windows` | Rebuild after confirming `<SubSystem>Windows</SubSystem>` in both Debug and Release `<Link>` sections |

---

### Step 5 — Build all three together (recommended)

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild RansomShield.sln /p:Configuration=Debug /p:Platform=x64 /v:minimal /nologo
```

When building through the `.sln`, MSBuild sets `$(SolutionDir)` automatically — no need to pass it explicitly. All three projects build in a single invocation.

---

## CI and releases

[`.github/workflows/build-and-release.yml`](.github/workflows/build-and-release.yml) builds the solution (Release x64) on GitHub's hosted `windows-2025` runner, which has Visual Studio 2026 with the v145 toolset. The WDK and SDK come from the same NuGet packages as a local build. The workflow then runs the host-runnable certification gates through [`Invoke-AllGates.ps1`](certification/scripts/Invoke-AllGates.ps1): Code Analysis, CodeQL, BinSkim, InfVerif and signed-catalog packaging.

| Trigger | What runs |
|---------|-----------|
| Pull request | Build + gates (CodeQL is skipped to keep pull requests quick) |
| Push to `main`, manual run | Build + all gates |
| Tag `vX.Y.Z` or `vX.Y.Z-suffix` | Build + all gates, then a GitHub Release (a suffix such as `-rc.1` makes it a pre-release) |

Each run uploads the gate evidence as the `certification-evidence` artifact and, when the build and gates pass, a ready-to-deploy ZIP as `release-payload`. CodeQL results also go to the repository's code scanning alerts; BinSkim's are in the evidence artifact (code scanning does not accept BinSkim's SARIF as BinSkim writes it). A failing gate fails the run, so a tag whose build fails a gate publishes nothing. Driver Verifier and the functional tests need a test VM and are not part of CI; see [`certification/README.md`](certification/README.md).

### Publishing a release

```powershell
git tag -a v1.1.0 -m "RansomShield 1.1.0"
git push origin v1.1.0
```

The workflow stamps the tag's version (`1.1.0.0` here) into the driver's version resource, the INF and the WDK project with [`Set-RsVersion.ps1`](certification/scripts/Set-RsVersion.ps1), then builds, runs all gates and publishes:

| Asset | Contents |
|-------|----------|
| `RansomShield-v1.1.0-x64.zip` | `RansomShield.sys`, `RansomShieldClient.exe`, `RansomShieldTray.exe`, the INF, `Deploy-RansomShield.ps1`, this README, `INSTALL.md`, and the certification scripts and tools |
| `RansomShield-v1.1.0-certification-evidence.zip` | Gate reports, logs and SARIF from that build |
| `SHA256SUMS.txt` | SHA-256 of each ZIP |

The release notes include the gate report, and in a public repository each ZIP also gets a build-provenance attestation. To set the version of a local build instead, run `.\certification\scripts\Set-RsVersion.ps1 -Version 1.1.0.0`.

### Installing a release

> **Test builds only.** Release binaries are not production-signed (no EV certificate or Microsoft attestation yet). `RansomShield.sys` loads only with test signing on and Memory Integrity (HVCI) off, so install it on a dedicated test machine or VM.

1. Check the download: compare `Get-FileHash .\RansomShield-v1.1.0-x64.zip` with `SHA256SUMS.txt`, or run `gh attestation verify .\RansomShield-v1.1.0-x64.zip --repo ocanaChris2/RansomShield`.
2. Turn on test signing (`bcdedit /set testsigning on`) and reboot.
3. Extract the ZIP, open an elevated PowerShell in the extracted folder and run `.\Deploy-RansomShield.ps1 -Configuration Release -SkipBuild`. The script signs the driver with a local test certificate (it needs `signtool.exe` from the Windows SDK), installs and loads it, and starts the tray agent.

To remove it, run `.\Deploy-RansomShield.ps1 -Action uninstall`.

---

## Deployment

### Quick deploy (PowerShell script)

```powershell
# Build, self-sign, install, and load in one step (requires admin + test signing)
.\Deploy-RansomShield.ps1

# Release build
.\Deploy-RansomShield.ps1 -Configuration Release

# Skip rebuild and re-install existing binary
.\Deploy-RansomShield.ps1 -SkipBuild

# Install pre-built Release binaries (for example, an extracted GitHub Release)
.\Deploy-RansomShield.ps1 -Configuration Release -SkipBuild

# Check driver status
.\Deploy-RansomShield.ps1 -Action status

# Unload and uninstall
.\Deploy-RansomShield.ps1 -Action uninstall
```

The script automatically:
- Verifies test signing (`bcdedit /set testsigning on`) and HVCI status.
- Builds all three projects: driver, CLI client, and tray agent.
- Creates or reuses a self-signed code-signing certificate (`CN=RansomShield Test Signing`).
- Trusts the cert in `LocalMachine\Root` and `LocalMachine\TrustedPublisher`.
- Copies the binary to `%SystemRoot%\System32\drivers\`, writes service registry entries directly (avoids `sc.exe` pending-deletion race), and calls `fltmc load`.
- Launches `RansomShieldTray.exe` automatically after a successful install so monitoring begins immediately.
- On uninstall: stops the tray agent and the CLI, removes the tray's auto-start task (and the `Run` entry older versions used), then unloads and deletes the driver service.

The driver must be signed to load (it is linked with `/INTEGRITYCHECK`), so use `-SkipSign` only if you sign `RansomShield.sys` yourself.

### Manual steps

```cmd
:: 1. Enable test signing (reboot after)
bcdedit /set testsigning on

:: 2. Install via INF
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 .\RansomShield.inf

:: 3. Verify the filter is loaded at altitude 325010
fltmc

:: 4. Start the tray agent (as Administrator)
x64\Debug\RansomShieldTray.exe

:: 5. Unload driver
fltmc unload RansomShield
```

### Driver auto-start

The INF registers the driver with `StartType = 1` (`SERVICE_SYSTEM_START`), so it loads automatically during kernel initialization on every boot — before any user process can run. `Deploy-RansomShield.ps1` instead registers it as demand-start (`Start = 3`) and loads it with `fltmc load`, so a script-deployed driver does not load at boot. To make an already-installed driver start at boot without reinstalling:

```cmd
sc config RansomShield start= system
```

### Tray agent auto-start

The tray agent auto-start is managed from its own context menu (right-click the shield icon → **Start with Windows**). This registers a Task Scheduler task, `RansomShieldTray`, that starts the tray at logon with the highest available privileges (it needs administrator rights to connect to the driver). Older versions used an `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry instead; the tray deletes it when it starts. The deploy script's `-Action uninstall` removes both.

### Deploy troubleshooting

#### Pre-flight failures

| Script output | Cause | Fix |
|---------------|-------|-----|
| `[ERR] Test signing is NOT enabled.` | BCD test-signing flag is off | Run `bcdedit /set testsigning on` from an elevated prompt, then **reboot** before re-running the script. The reboot is mandatory — bcdedit changes only take effect at the next boot |
| `[ERR] Memory Integrity (HVCI) is ENABLED` | Hypervisor-Protected Code Integrity blocks all non-WHQL-signed drivers regardless of test-signing mode | Open **Windows Security** → Device Security → Core isolation → Memory integrity → turn **OFF** → reboot. This cannot be bypassed with any signing trick in test mode |

#### Signing failures

| Script output | Cause | Fix |
|---------------|-------|-----|
| `signtool.exe not found under Windows Kits` | Windows SDK not installed, or installed to a non-standard path | Install the **Windows 10/11 SDK** via VS Installer (Individual components → "Windows 10/11 SDK") — `signtool.exe` lives under `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\`. Alternatively, run with `-SkipSign` if you manage signing externally |
| `signtool failed (exit 1)` | Certificate not trusted or wrong hash algorithm | The script creates `CN=RansomShield Test Signing` automatically. If the cert exists but is expired or has no private key, delete it from `Cert:\CurrentUser\My` and re-run |
| `Post-sign verification: status=UnknownError` | Signature applied but not verifiable — often a timestamp server failure | The script signs without a timestamp server (offline-friendly). If the `.sys` was already loaded and locked by a previous `fltmc load`, sign fails. Unload first with `fltmc unload RansomShield`, then re-run |

#### Load failures

| Script output / symptom | Cause | Fix |
|--------------------------|-------|-----|
| `[ERR] Driver is in a stuck state: service RUNNING but filter not in fltmc.` | The driver's `DriverUnload` callback ran and `FltUnregisterFilter` succeeded, removing it from FltMgr's list, but the kernel still holds a reference to the image. SCM shows RUNNING because the service object was not cleaned up. | **Reboot** — this state cannot be resolved without one. After reboot, the driver will not auto-start (it is registered as `DEMAND_START`, Start type 3), so the next `Deploy-RansomShield.ps1` run will succeed |
| `fltmc load failed` + Code Integrity events in the log | Test signing not enabled after bcdedit | Confirm you rebooted after running `bcdedit /set testsigning on`. Verify with `bcdedit /enum {current}` — look for `testsigning Yes` |
| `fltmc load failed` + Code Integrity Event ID 3077 or 3033 | Driver image not signed, or signed with an untrusted certificate | Re-run the script without `-SkipSign` to apply the test signature. Confirm the cert is in `LocalMachine\TrustedPublisher` |
| `fltmc load failed: ERROR_SERVICE_ALREADY_RUNNING (0x80070420)` | A previous `sc.exe delete` or registry removal left the service in a "pending deletion" state while the driver image is still referenced by the kernel | The script uses direct registry writes (`New-Item -Force`) instead of `sc.exe create` specifically to avoid this race. If you hit it via manual steps, reboot to clear the pending deletion |
| `fltmc load` succeeds but driver immediately unloads | `DriverEntry` returned a failure status | Check the kernel debugger or use `!analyze -v` in WinDbg. Common cause: `FltRegisterFilter` failed because a required registry key (the `Instances\RansomShield\Altitude` entry) is missing — the script writes it directly, but `rundll32 InstallHinfSection` relies on the INF |
| Client cannot connect: `FilterConnectCommunicationPort` returns `ERROR_FILE_NOT_FOUND` | Driver is not loaded, or `\RansomShieldPort` was never created | Run `fltmc` to confirm the driver is at altitude 325010. If missing, re-run `Deploy-RansomShield.ps1` |
| Client cannot connect: `ERROR_ACCESS_DENIED` | Running the client without administrator privileges | The communication port ACL only grants access to SYSTEM and Administrators. Launch the client from an elevated prompt |

#### Uninstall

```powershell
.\Deploy-RansomShield.ps1 -Action uninstall
```

The script: unloads the filter (`fltmc unload`), stops and deletes the SCM service (`sc.exe delete`), and removes `%SystemRoot%\System32\drivers\RansomShield.sys`. If the driver is in the stuck state described above, `fltmc unload` may fail — reboot and do not reinstall until after the next boot.

---

## IRQL and memory rules

| Rule | Reason |
|------|--------|
| All `RS_PROCESS_CONTEXT` in `NonPagedPoolNx` | Accessed at `DISPATCH_LEVEL` under the spinlock |
| `FltSendMessage` called after `KeReleaseSpinLock` | Requires `PASSIVE_LEVEL` |
| `SeLocateProcessImageName` guarded by `KeGetCurrentIrql() == PASSIVE_LEVEL` | Requires `PASSIVE_LEVEL` |
| Do **not** call `ObDereferenceObject` on `FltGetRequestorProcess()` result | Returns unreferenced pointer tied to callback data lifetime |
| Copy needed fields to stack locals before releasing `g_ContextLock` | Prevents use-after-free when another thread unblocks or removes the context (`RsUnblockProcess`, process exit) |
| Allowlist string literals in `.rdata` (non-paged) | Safe to read at `DISPATCH_LEVEL` |
| Dynamic allowlist under its own push lock (`g_AllowlistLock`), never under the spinlock | The comparison reads the paged image-name buffer, which is legal only at or below `APC_LEVEL` |
| `DbgPrint` with `%wZ`/`%ws` only at `PASSIVE_LEVEL`, after releasing the spinlock | Unicode format conversion can touch paged memory |
| Port message buffers copied in and out under `__try/__except`, never while holding a lock | User-mode buffers can be invalid or change at any time |

---

## Configuration defaults

| Setting | Default | Accepted range | Registry value |
|---------|---------|----------------|---------------|
| File count threshold | 50 ops | 1–256 | `HKLM\...\RansomShield\Config\FileCountThreshold` |
| Time window | 10 s | 1–3600 s | `HKLM\...\RansomShield\Config\TimeWindowSeconds` |
| Monitoring enabled | `TRUE` | — | `HKLM\...\RansomShield\Config\MonitoringEnabled` |
| Max allowlist entries | 128 | — | — |
| Allowlist chunk size | 32 entries/msg | — | — |
| Max tracked processes | 1024 | fixed (`RS_MAX_TRACKED_PIDS`) | — |

The driver rejects threshold and window values outside these ranges, and `RansomShieldClient.exe --set-threshold` refuses them. When the tray agent or the CLI reads the registry, a value of 0 falls back to the default and an out-of-range value is clamped to the nearest limit. The threshold is capped at 256 because each process keeps only its last 256 operation timestamps: a higher threshold could never be reached and would silently turn blocking off.

---

## File map

**Kernel driver**

| File | Role |
|------|------|
| `RansomShield.c` | `DriverEntry`, filter registration, IRP callbacks, unload |
| `RsContext.c` | Per-PID hash table, LRU cap, heuristic evaluation, allowlist, process-exit cleanup |
| `RsCommPort.c` | FltMgr communication port setup and message dispatch |
| `RansomShield.h` | All kernel types, constants, and function declarations |
| `RansomShield.rc` | Version resource (set by `Set-RsVersion.ps1`) |

**Shared**

| File | Role |
|------|------|
| `SharedDefs.h` | Protocol structures and message types shared between kernel and user mode |
| `CommManager.h/.cpp` | Singleton; wraps `FilterConnect/Send/GetMessage`; background listener thread |
| `ConfigManager.h/.cpp` | Registry persistence for thresholds and allowlist |
| `EventLogger.h/.cpp` | Windows Event Log + local file log |
| `RansomShieldModule.h/.cpp` | Implements `IProtectionModule`; owns and coordinates `CommManager`, `ConfigManager` and `EventLogger` |
| `sdk/IProtectionModule.h` | Abstract interface for a protection module, so a host process can manage several modules the same way |

**CLI client (`RansomShieldClient.exe`)**

| File | Role |
|------|------|
| `Main.cpp` | CLI argument dispatch, daemon loop with 60 s health checks |

**Tray agent (`RansomShieldTray.exe`)**

| File | Role |
|------|------|
| `TrayMain.cpp` | `WinMain`, hidden message window, WndProc, reconnect timer |
| `NotificationManager.h/.cpp` | `Shell_NotifyIcon` tray icon, balloon-tip alerts, right-click context menu, auto-start toggle |

**Deployment**

| File | Role |
|------|------|
| `Deploy-RansomShield.ps1` | Build all three projects, self-sign, install driver, launch tray agent; uninstall support |
| `RansomShield.inf` | Driver installation descriptor — altitude 325010, `StartType = 1` (system-start) |

**CI and certification**

| File | Role |
|------|------|
| `.github/workflows/build-and-release.yml` | Builds and runs the certification gates on pull requests and `main`; publishes a GitHub Release from `v*` tags |
| `certification/scripts/Invoke-AllGates.ps1` | Runs the host-runnable certification gates and writes the evidence bundle |
| `certification/scripts/Set-RsVersion.ps1` | Stamps one version into `RansomShield.rc`, the INF and the WDK project |
| `certification/tools/` | Test-VM tools: `RansomSim.ps1`, `Workload-FalsePositive.ps1`, `Workload-ProcessChurn.ps1` |
