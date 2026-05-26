/*++
Module Name:
    Main.cpp

Abstract:
    Entry point for the RansomShield user-mode control application.
    Provides:
      - Administrator privilege check.
      - CLI argument parsing for interactive commands.
      - Service loop mode for running as a Windows Service.
      - Startup sequence: load config → connect to driver → push config → listen.

    USAGE:
      RansomShield.exe [command] [options]

    COMMANDS:
      (no args)                  Start in service/daemon mode (connect & listen).
      --status                   Query and display current driver status.
      --set-threshold <count> <seconds>
                                 Set heuristic threshold: file count and time window.
      --add-exception <name>     Add a process image name to the allowlist.
      --remove-exception <name>  Remove a process image name from the allowlist.
      --list-exceptions          Display all allowlist entries.
      --unblock <pid>            Unblock a previously blocked process.
      --list-blocked             List all currently blocked PIDs.
      --pause                    Pause monitoring (driver stops blocking).
      --resume                   Resume monitoring after pause.
      --push-config              Push current registry config to driver.
      --help                     Show usage information.

Author:
    RansomShield Development
--*/

#include <Windows.h>
#include <FltUser.h>
#include <cstdio>
#include <string>
#include <algorithm>

#include "../common/RansomShieldModule.h"

// Module-level protection engine instance.
static RansomShieldModule g_module;

// ============================================================================
// PRIVILEGE CHECK
// ============================================================================

static bool IsElevated()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminSid = NULL;
    if (!AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminSid)) {
        return false;
    }
    CheckTokenMembership(NULL, adminSid, &isAdmin);
    FreeSid(adminSid);
    return (isAdmin != FALSE);
}

// ============================================================================
// CLI COMMAND HANDLERS
// ============================================================================

static int CmdStatus()
{
    if (!g_module.Comm().IsConnected()) {
        wprintf(L"RansomShield: Not connected to driver. Attempting to connect...\n");
        if (FAILED(g_module.Connect())) return 1;
    }

    RS_REPLY_CONFIG config = {};
    HRESULT hr = g_module.Comm().QueryConfig(config);
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Failed to query driver config: 0x%08X\n", hr);
        return 1;
    }

    wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
    wprintf(L"║  RansomShield Driver Status                     ║\n");
    wprintf(L"╠══════════════════════════════════════════════════╣\n");
    wprintf(L"║  Monitoring:      %-30s ║\n", config.MonitoringEnabled ? L"ACTIVE" : L"PAUSED");
    wprintf(L"║  Threshold:       %-6lu files                   ║\n", config.FileCountThreshold);
    wprintf(L"║  Time Window:     %-6lu seconds                 ║\n", config.TimeWindowSeconds);
    wprintf(L"║  Tracked PIDs:    %-6lu                         ║\n", config.TrackedPidCount);
    wprintf(L"║  Blocked PIDs:    %-6lu                         ║\n", config.BlockedPidCount);
    wprintf(L"╚══════════════════════════════════════════════════╝\n\n");

    if (config.BlockedPidCount > 0) {
        RS_REPLY_BLOCKED_PIDS blocked = {};
        hr = g_module.Comm().QueryBlockedPids(blocked);
        if (SUCCEEDED(hr) && blocked.Count > 0) {
            wprintf(L"  Blocked Processes:\n");
            wprintf(L"  %-8s %-30s %-12s %s\n", L"PID", L"Image Name", L"Ops Count", L"Status");
            wprintf(L"  %-8s %-30s %-12s %s\n", L"--------",
                    L"------------------------------", L"------------", L"------");
            for (ULONG i = 0; i < blocked.Count; i++) {
                wprintf(L"  %-8lu %-30s %-12lu BLOCKED\n",
                        blocked.Entries[i].ProcessId,
                        blocked.Entries[i].ImageName,
                        blocked.Entries[i].OperationCount);
            }
            wprintf(L"\n");
        }
    }
    return 0;
}

static int CmdSetThreshold(int argc, wchar_t* argv[])
{
    if (argc < 4) {
        fwprintf(stderr, L"Usage: RansomShield.exe --set-threshold <fileCount> <seconds>\n");
        return 1;
    }

    ULONG fileCount = static_cast<ULONG>(_wtoi(argv[2]));
    ULONG seconds   = static_cast<ULONG>(_wtoi(argv[3]));
    if (fileCount == 0 || seconds == 0) {
        fwprintf(stderr, L"RansomShield: Both values must be > 0.\n");
        return 1;
    }

    g_module.Config().SetFileCountThreshold(fileCount);
    g_module.Config().SetTimeWindowSeconds(seconds);

    if (g_module.Comm().IsConnected()) g_module.PushToDriver();

    wprintf(L"RansomShield: Threshold updated to %lu files in %lu seconds.\n", fileCount, seconds);
    return 0;
}

static int CmdAddException(const std::wstring& imageName)
{
    if (imageName.empty()) {
        fwprintf(stderr, L"Usage: RansomShield.exe --add-exception <imageName>\n");
        return 1;
    }
    if (!g_module.Config().AddException(imageName)) return 1;
    g_module.Config().SaveToRegistry();
    if (g_module.Comm().IsConnected()) g_module.PushToDriver();
    return 0;
}

static int CmdRemoveException(const std::wstring& imageName)
{
    if (imageName.empty()) {
        fwprintf(stderr, L"Usage: RansomShield.exe --remove-exception <imageName>\n");
        return 1;
    }
    if (!g_module.Config().RemoveException(imageName)) return 1;
    g_module.Config().SaveToRegistry();
    if (g_module.Comm().IsConnected()) g_module.PushToDriver();
    return 0;
}

static int CmdListExceptions()
{
    auto exceptions = g_module.Config().GetExceptions();
    wprintf(L"\n  RansomShield Allowlist (%zu entries):\n", exceptions.size());
    wprintf(L"  ─────────────────────────────────────\n");
    if (exceptions.empty()) {
        wprintf(L"  (empty)\n");
    } else {
        for (size_t i = 0; i < exceptions.size(); i++) {
            wprintf(L"  %3zu. %s\n", i + 1, exceptions[i].c_str());
        }
    }
    wprintf(L"\n");
    return 0;
}

static int CmdUnblock(ULONG pid)
{
    if (pid == 0) {
        fwprintf(stderr, L"Usage: RansomShield.exe --unblock <pid>\n");
        return 1;
    }
    if (!g_module.Comm().IsConnected()) {
        wprintf(L"RansomShield: Not connected. Attempting to connect...\n");
        if (FAILED(g_module.Connect())) return 1;
    }
    RS_REPLY_UNBLOCK_PID reply = {};
    HRESULT hr = g_module.Comm().UnblockPid(pid, reply);
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Unblock command failed: 0x%08X\n", hr);
        return 1;
    }
    return 0;
}

static int CmdListBlocked()
{
    if (!g_module.Comm().IsConnected()) {
        wprintf(L"RansomShield: Not connected. Attempting to connect...\n");
        if (FAILED(g_module.Connect())) return 1;
    }
    RS_REPLY_BLOCKED_PIDS reply = {};
    HRESULT hr = g_module.Comm().QueryBlockedPids(reply);
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: QueryBlockedPids failed: 0x%08X\n", hr);
        return 1;
    }
    if (reply.Count == 0) {
        wprintf(L"  No blocked processes.\n");
    } else {
        wprintf(L"\n  Blocked Processes (%lu):\n", reply.Count);
        wprintf(L"  %-8s %-30s %-12s\n", L"PID", L"Image Name", L"Ops");
        wprintf(L"  %-8s %-30s %-12s\n",
                L"--------", L"------------------------------", L"------------");
        for (ULONG i = 0; i < reply.Count; i++) {
            wprintf(L"  %-8lu %-30s %-12lu\n",
                    reply.Entries[i].ProcessId,
                    reply.Entries[i].ImageName,
                    reply.Entries[i].OperationCount);
        }
        wprintf(L"\n");
    }
    return 0;
}

static int CmdPause()
{
    if (!g_module.Comm().IsConnected()) {
        if (FAILED(g_module.Connect())) return 1;
    }
    HRESULT hr = g_module.Comm().PauseMonitoring();
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Pause failed: 0x%08X\n", hr);
        return 1;
    }
    g_module.Config().SetMonitoringEnabled(false);
    return 0;
}

static int CmdResume()
{
    if (!g_module.Comm().IsConnected()) {
        if (FAILED(g_module.Connect())) return 1;
    }
    HRESULT hr = g_module.Comm().ResumeMonitoring();
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Resume failed: 0x%08X\n", hr);
        return 1;
    }
    g_module.Config().SetMonitoringEnabled(true);
    return 0;
}

static int CmdPushConfig()
{
    if (!g_module.Comm().IsConnected()) {
        if (FAILED(g_module.Connect())) return 1;
    }
    return g_module.PushToDriver() ? 0 : 1;
}

// ============================================================================
// SERVICE/DAEMON MODE
// ============================================================================

static int RunDaemonMode()
{
    wprintf(L"RansomShield: Starting in daemon mode...\n\n");

    g_module.Initialize();

    HRESULT hr = g_module.Connect();
    if (FAILED(hr)) {
        g_module.Logger().LogWarning(L"Cannot connect to RansomShield driver. Retrying...");
        for (int attempt = 0; attempt < 12; attempt++) {
            Sleep(10000);
            hr = g_module.Connect();
            if (SUCCEEDED(hr)) break;
        }
        if (FAILED(hr)) {
            g_module.Logger().LogError(L"Cannot connect to driver after 2 minutes. Exiting.");
            return 1;
        }
    }

    g_module.PushToDriver();

    hr = g_module.StartListener([](const BYTE* data, DWORD dataSize) {
        g_module.Logger().HandleNotification(data, dataSize);
    });
    if (FAILED(hr)) {
        g_module.Logger().LogError(L"Failed to start notification listener.");
        return 1;
    }

    g_module.Logger().LogInfo(L"RansomShield daemon is running.");
    wprintf(L"RansomShield: Daemon running. Press Ctrl+C to stop.\n\n");

    int pollCounter = 0;
    while (g_module.Comm().IsConnected()) {
        Sleep(5000);
        if (++pollCounter >= 12) {
            pollCounter = 0;
            RS_REPLY_CONFIG cfg = {};
            if (FAILED(g_module.Comm().QueryConfig(cfg))) {
                g_module.Logger().LogWarning(L"Driver health check failed. Reconnecting...");
                g_module.Disconnect();
                if (SUCCEEDED(g_module.Connect())) {
                    g_module.Logger().LogInfo(L"Reconnected to driver.");
                    g_module.PushToDriver();
                    g_module.StartListener([](const BYTE* data, DWORD dataSize) {
                        g_module.Logger().HandleNotification(data, dataSize);
                    });
                }
            }
        }
    }

    g_module.Logger().LogInfo(L"RansomShield daemon shutting down.");
    g_module.Shutdown();
    return 0;
}

// ============================================================================
// USAGE
// ============================================================================

static void PrintUsage()
{
    wprintf(L"\nRansomShield — Ransomware Protection Control Application\n");
    wprintf(L"═════════════════════════════════════════════════════════\n\n");
    wprintf(L"USAGE: RansomShield.exe [command] [options]\n\n");
    wprintf(L"COMMANDS:\n");
    wprintf(L"  (no args)                        Start in daemon mode\n");
    wprintf(L"  --status                         Query current driver status\n");
    wprintf(L"  --set-threshold <count> <secs>   Set heuristic threshold\n");
    wprintf(L"  --add-exception <name>           Add process to allowlist\n");
    wprintf(L"  --remove-exception <name>        Remove process from allowlist\n");
    wprintf(L"  --list-exceptions                Display all allowlist entries\n");
    wprintf(L"  --unblock <pid>                  Unblock a previously blocked process\n");
    wprintf(L"  --list-blocked                   List all currently blocked PIDs\n");
    wprintf(L"  --pause                          Pause monitoring\n");
    wprintf(L"  --resume                         Resume monitoring\n");
    wprintf(L"  --push-config                    Push registry config to driver\n");
    wprintf(L"  --help                           Show this help message\n\n");
    wprintf(L"NOTE: Requires Administrator privileges.\n\n");
}

// ============================================================================
// ENTRY POINT
// ============================================================================

int __cdecl wmain(int argc, wchar_t* argv[])
{
    if (!IsElevated()) {
        fwprintf(stderr, L"\nRansomShield: ERROR — requires Administrator privileges.\n\n");
        return 1;
    }

    if (argc < 2) return RunDaemonMode();

    std::wstring command = argv[1];
    std::transform(command.begin(), command.end(), command.begin(), ::towlower);

    if (command == L"--help" || command == L"-h" || command == L"/?") {
        PrintUsage();
        return 0;
    }

    g_module.Initialize();

    if (command == L"--status")           return CmdStatus();
    if (command == L"--set-threshold")    return CmdSetThreshold(argc, argv);
    if (command == L"--add-exception") {
        if (argc < 3) { fwprintf(stderr, L"Usage: --add-exception <imageName>\n"); return 1; }
        return CmdAddException(argv[2]);
    }
    if (command == L"--remove-exception") {
        if (argc < 3) { fwprintf(stderr, L"Usage: --remove-exception <imageName>\n"); return 1; }
        return CmdRemoveException(argv[2]);
    }
    if (command == L"--list-exceptions")  return CmdListExceptions();
    if (command == L"--unblock") {
        if (argc < 3) { fwprintf(stderr, L"Usage: --unblock <pid>\n"); return 1; }
        return CmdUnblock(static_cast<ULONG>(_wtoi(argv[2])));
    }
    if (command == L"--list-blocked")     return CmdListBlocked();
    if (command == L"--pause")            return CmdPause();
    if (command == L"--resume")           return CmdResume();
    if (command == L"--push-config")      return CmdPushConfig();

    fwprintf(stderr, L"RansomShield: Unknown command '%s'. Use --help.\n", argv[1]);
    return 1;
}
