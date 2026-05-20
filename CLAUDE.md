# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

**Prerequisites:** Visual Studio 2025 (v145 toolset), `nuget.exe` in repo root.
WDK kernel headers and libs come from NuGet — no WDK installation required.

```powershell
# One-time: restore WDK NuGet packages into packages\ (version 10.0.26100.6584)
.\nuget.exe restore RansomShield.sln -PackagesDirectory packages

# Build driver (Debug x64) → x64\Debug\RansomShield.sys
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild RansomShield.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir="$PWD\"

# Build driver (Release x64) → x64\Release\RansomShield.sys
& $msbuild RansomShield.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$PWD\"
```

**NuGet packages used** (defined in `packages.config`):
- `Microsoft.Windows.WDK.x64` — kernel-mode headers (`km/`, `shared/`) and libs (`fltMgr.lib`, `ntoskrnl.lib`, `BufferOverflowK.lib`, …)
- `Microsoft.Windows.SDK.CPP` — shared headers (`ntstatus.h`, `fltUserStructures.h`, `ntdef.h`, …) and user-mode headers (`Windows.h`, `FltUser.h`, …)
- `Microsoft.Windows.SDK.CPP.x64` — user-mode x64 libs (`fltLib.lib`, `advapi32.lib`, …)

**Build user-mode client** → `x64\Debug\RansomShieldClient.exe`:
```powershell
& $msbuild RansomShieldClient.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir="$PWD\"
& $msbuild RansomShieldClient.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$PWD\"
```

**Build tray agent** → `x64\Debug\RansomShieldTray.exe`:
```powershell
& $msbuild RansomShieldTray.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SolutionDir="$PWD\"
& $msbuild RansomShieldTray.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$PWD\"
```

**Build all three together** via solution:
```powershell
& $msbuild RansomShield.sln /p:Configuration=Debug /p:Platform=x64
```

**Driver deployment (requires test signing):**
```cmd
bcdedit /set testsigning on   # reboot after
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 .\RansomShield.inf
fltmc                          # verify RansomShield appears at altitude 325010
fltmc unload RansomShield      # unload
```

## Architecture

This is a two-component Windows security system:

1. **Kernel driver** (`RansomShield.sys`) — WDM minifilter that blocks ransomware
2. **User-mode client** (`RansomShieldClient.exe`) — C++ CLI + daemon for monitoring and control

### Kernel Driver

Registers with the Windows Filter Manager (FltMgr) at altitude **325010** (Anti-Virus range). Monitors two I/O operation types:

- `IRP_MJ_WRITE` (pre-op, skips paging I/O): catches file overwrite/encryption
- `IRP_MJ_SET_INFORMATION` (pre+post): catches renames (extension changes) and deletes

**Heuristic engine** (`Context.c`):
The core detection mechanism. Tracks per-PID file modification events using a sliding time window. When a process exceeds **50 operations in 10 seconds**, it is flagged and all subsequent writes/renames/deletes are blocked with `STATUS_ACCESS_DENIED`.

- Storage: fixed-size hash table (1021 prime buckets, separate chaining via `LIST_ENTRY`) in `NonPagedPoolNx`
- Per-PID ring buffer: 256 `LONGLONG` timestamps (100ns ticks via `KeQueryInterruptTime`)
- Single global spinlock (`g_ContextLock`) protects the entire table; critical section is intentionally short
- Blocked state is **sticky** — only cleared by explicit user-mode unblock command
- New context allocation uses double-checked locking: allocate at PASSIVE_LEVEL, re-acquire spinlock, re-check, insert or free the loser

**Communication port** (`CommPort.c`):
Kernel↔user channel via FltMgr port at `\RansomShieldPort`.
- One client at a time (admin-only via security descriptor)
- Kernel→User: `FltSendMessage` with 5-second timeout (called after releasing spinlock, at PASSIVE_LEVEL)
- User→Kernel: `FilterSendMessage`/`FilterGetMessage` for queries and commands

| Kernel file | Responsibility |
|---|---|
| `RansomShield.c` | `DriverEntry`, filter registration, operation callbacks |
| `Context.c` | Per-PID hash table, heuristic evaluation, allowlist |
| `CommPort.c` | FltMgr communication port setup and message dispatch |
| `RansomShield.h` | All kernel types, constants, and function declarations |

### User-Mode Client (`RansomShieldClient.exe`)

| File | Responsibility |
|---|---|
| `Main.cpp` | CLI argument dispatch, daemon loop with 60s health checks |
| `CommManager.h/.cpp` | Singleton; wraps `FilterConnect/Send/GetMessage`; listener thread |
| `ConfigManager.h/.cpp` | Registry persistence under `HKLM\...\RansomShield\Config` |
| `EventLogger.h/.cpp` | Windows Event Log via `ReportEvent` |
| `SharedDefs.h` | All protocol structures shared between kernel and user mode |

### Tray Agent (`RansomShieldTray.exe`)

Windows-subsystem background application (no console window). Reuses `CommManager`, `ConfigManager`, and `EventLogger` from the CLI client.

| File | Responsibility |
|---|---|
| `TrayMain.cpp` | `WinMain` entry point, hidden message window, WndProc, 5 s reconnect timer |
| `NotificationManager.h/.cpp` | `Shell_NotifyIcon` tray icon (UAC shield), thread-safe alert queue, `NIIF_WARNING` balloon tips, right-click context menu, HKCU auto-start toggle |

**Key design points:**
- The comm port allows only one client — while the tray is running it holds the connection; CLI commands that need the port must be run after stopping the tray.
- Listener thread pushes `RsAlertData` to a `std::queue` (mutex-protected) and calls `PostMessage(WM_RSBLOCKED)` to marshal to the main thread, which shows the balloon.
- Single-instance guard via named mutex (`Global\RansomShieldTrayMutex_3F7A`).
- Driver start type is `SERVICE_SYSTEM_START` (1) — set in `RansomShield.inf` and applied with `sc config RansomShield start= system`.

`CommManager` runs a background thread calling `FilterGetMessage()` in a loop to receive driver push notifications. `ConfigManager` persists thresholds and allowlist to registry; `PushToDriver()` sends them via chunked allowlist messages.

### Protocol (`SharedDefs.h`)

All messages begin with `RS_MESSAGE_HEADER` (type, size, sequence number, protocol version). Type number ranges:
- `1–99`: Kernel→User unsolicited notifications
- `100–199`: User→Kernel queries (request/reply)
- `200–299`: User→Kernel commands (request/reply)
- `300–399`: User→Kernel configuration (request/reply)

### Critical IRQL / Memory Rules

- All `RS_PROCESS_CONTEXT` structures must be in `NonPagedPoolNx` — accessed at `DISPATCH_LEVEL` under the spinlock
- `FltSendMessage` must be called at `PASSIVE_LEVEL` — always after `KeReleaseSpinLock`
- `SeLocateProcessImageName` requires `PASSIVE_LEVEL` — guarded by `KeGetCurrentIrql() == PASSIVE_LEVEL`
- **Do not call `ObDereferenceObject`** on pointers from `FltGetRequestorProcess()` — it returns an unreferenced pointer tied to the callback data lifetime
- Allowlist string literals are in `.rdata` (non-paged, safe at `DISPATCH_LEVEL`)
- After releasing `g_ContextLock`, do not access `context` pointer — copy needed fields to stack locals first (use-after-free risk from concurrent `RsUnblockProcess`)
