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

    EXAMPLES:
      RansomShield.exe --set-threshold 100 15
      RansomShield.exe --add-exception code.exe
      RansomShield.exe --unblock 4816
      RansomShield.exe --status

    PRIVILEGE CHECK:
    The application requires Administrator or SYSTEM privileges because:
      1. FilterConnectCommunicationPort requires SeLoadDriverPrivilege.
      2. Writing to HKLM\...\Services requires Administrator access.
      3. Managing a kernel driver's configuration should be restricted.

    We check for admin privileges on startup and refuse to run if
    not elevated. The check uses CheckTokenMembership() to test for
    membership in the Administrators group, which works correctly
    even with UAC split tokens.

Author:
    RansomShield Development
--*/

#include <Windows.h>
#include <FltUser.h>
#include <cstdio>
#include <string>
#include <algorithm>

#include "SharedDefs.h"
#include "CommManager.h"
#include "ConfigManager.h"
#include "EventLogger.h"

// ============================================================================
// PRIVILEGE CHECK
// ============================================================================

/*++
Routine Description:
    Checks if the current process is running with Administrator privileges.

    On Windows Vista+, even if the user is an Administrator, the process
    runs with a filtered token (standard user) unless explicitly elevated
    ("Run as Administrator"). This function checks the ELEVATED token,
    not just the user's group membership.

    HOW IT WORKS:
    1. Allocate a SID for the Administrators group (SECURITY_NT_AUTHORITY).
    2. CheckTokenMembership() checks if the SID is enabled in the
       current token. This correctly handles UAC split tokens:
       - Elevated admin:  SID is enabled → TRUE
       - Filtered admin:  SID is present but not enabled → FALSE
       - Standard user:   SID is not present → FALSE

Return Value:
    TRUE  - Process is running elevated (Administrator or SYSTEM).
    FALSE - Process is NOT elevated.
--*/
bool IsElevated()
{
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    //
    // AllocateAndInitializeSid creates a SID for the given authority
    // and sub-authority values. DOMAIN_ALIAS_RID_ADMINS (0x220) is
    // the well-known RID for the Administrators group.
    //
    PSID adminSid = NULL;
    if (!AllocateAndInitializeSid(
            &ntAuth,
            2,                              // SubAuthority count
            SECURITY_BUILTIN_DOMAIN_RID,    // SubAuthority[0] = BUILTIN domain
            DOMAIN_ALIAS_RID_ADMINS,        // SubAuthority[1] = Administrators
            0, 0, 0, 0, 0, 0,              // Remaining sub-authorities (unused)
            &adminSid)) {
        fwprintf(stderr, L"RansomShield: AllocateAndInitializeSid failed: %lu\n", GetLastError());
        return false;
    }

    //
    // CheckTokenMembership checks if the specified SID is a member of
    // the current token's groups AND is enabled (not just present).
    // This is the correct way to check for admin elevation on Vista+.
    //
    if (!CheckTokenMembership(NULL, adminSid, &isAdmin)) {
        fwprintf(stderr, L"RansomShield: CheckTokenMembership failed: %lu\n", GetLastError());
        isAdmin = FALSE;
    }

    FreeSid(adminSid);

    return (isAdmin != FALSE);
}

// ============================================================================
// CLI COMMAND HANDLERS
// ============================================================================

static int CmdStatus()
{
    if (!CommManager::Instance().IsConnected()) {
        wprintf(L"RansomShield: Not connected to driver. Attempting to connect...\n");
        HRESULT hr = CommManager::Instance().Connect();
        if (FAILED(hr)) {
            return 1;
        }
    }

    //
    // Query driver configuration.
    //
    RS_REPLY_CONFIG config;
    ZeroMemory(&config, sizeof(config));

    HRESULT hr = CommManager::Instance().QueryConfig(config);
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

    //
    // Query blocked PIDs.
    //
    if (config.BlockedPidCount > 0) {
        RS_REPLY_BLOCKED_PIDS blocked;
        ZeroMemory(&blocked, sizeof(blocked));

        hr = CommManager::Instance().QueryBlockedPids(blocked);
        if (SUCCEEDED(hr) && blocked.Count > 0) {
            wprintf(L"  Blocked Processes:\n");
            wprintf(L"  %-8s %-30s %-12s %s\n", L"PID", L"Image Name", L"Ops Count", L"Status");
            wprintf(L"  %-8s %-30s %-12s %s\n", L"--------", L"------------------------------", L"------------", L"------");

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
    ULONG seconds = static_cast<ULONG>(_wtoi(argv[3]));

    if (fileCount == 0 || seconds == 0) {
        fwprintf(stderr, L"RansomShield: Invalid threshold values. Both must be > 0.\n");
        return 1;
    }

    ConfigManager::Instance().SetFileCountThreshold(fileCount);
    ConfigManager::Instance().SetTimeWindowSeconds(seconds);

    //
    // Push the updated config to the driver.
    //
    if (CommManager::Instance().IsConnected()) {
        ConfigManager::Instance().PushToDriver();
    }

    wprintf(L"RansomShield: Threshold updated to %lu files in %lu seconds.\n", fileCount, seconds);
    return 0;
}

static int CmdAddException(const std::wstring& imageName)
{
    if (imageName.empty()) {
        fwprintf(stderr, L"Usage: RansomShield.exe --add-exception <imageName>\n");
        return 1;
    }

    if (!ConfigManager::Instance().AddException(imageName)) {
        return 1;
    }

    ConfigManager::Instance().SaveToRegistry();

    if (CommManager::Instance().IsConnected()) {
        ConfigManager::Instance().PushToDriver();
    }

    return 0;
}

static int CmdRemoveException(const std::wstring& imageName)
{
    if (imageName.empty()) {
        fwprintf(stderr, L"Usage: RansomShield.exe --remove-exception <imageName>\n");
        return 1;
    }

    if (!ConfigManager::Instance().RemoveException(imageName)) {
        return 1;
    }

    ConfigManager::Instance().SaveToRegistry();

    if (CommManager::Instance().IsConnected()) {
        ConfigManager::Instance().PushToDriver();
    }

    return 0;
}

static int CmdListExceptions()
{
    auto exceptions = ConfigManager::Instance().GetExceptions();

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

    if (!CommManager::Instance().IsConnected()) {
        wprintf(L"RansomShield: Not connected to driver. Attempting to connect...\n");
        HRESULT hr = CommManager::Instance().Connect();
        if (FAILED(hr)) {
            return 1;
        }
    }

    RS_REPLY_UNBLOCK_PID reply;
    HRESULT hr = CommManager::Instance().UnblockPid(pid, reply);

    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Unblock command failed: 0x%08X\n", hr);
        return 1;
    }

    return 0;
}

static int CmdListBlocked()
{
    if (!CommManager::Instance().IsConnected()) {
        wprintf(L"RansomShield: Not connected to driver. Attempting to connect...\n");
        HRESULT hr = CommManager::Instance().Connect();
        if (FAILED(hr)) {
            return 1;
        }
    }

    RS_REPLY_BLOCKED_PIDS reply;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = CommManager::Instance().QueryBlockedPids(reply);
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: QueryBlockedPids failed: 0x%08X\n", hr);
        return 1;
    }

    if (reply.Count == 0) {
        wprintf(L"  No blocked processes.\n");
    } else {
        wprintf(L"\n  Blocked Processes (%lu):\n", reply.Count);
        wprintf(L"  %-8s %-30s %-12s\n", L"PID", L"Image Name", L"Ops");
        wprintf(L"  %-8s %-30s %-12s\n", L"--------", L"------------------------------", L"------------");

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
    if (!CommManager::Instance().IsConnected()) {
        wprintf(L"RansomShield: Not connected. Attempting to connect...\n");
        HRESULT hr = CommManager::Instance().Connect();
        if (FAILED(hr)) return 1;
    }

    HRESULT hr = CommManager::Instance().PauseMonitoring();
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Pause failed: 0x%08X\n", hr);
        return 1;
    }

    ConfigManager::Instance().SetMonitoringEnabled(false);
    return 0;
}

static int CmdResume()
{
    if (!CommManager::Instance().IsConnected()) {
        wprintf(L"RansomShield: Not connected. Attempting to connect...\n");
        HRESULT hr = CommManager::Instance().Connect();
        if (FAILED(hr)) return 1;
    }

    HRESULT hr = CommManager::Instance().ResumeMonitoring();
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Resume failed: 0x%08X\n", hr);
        return 1;
    }

    ConfigManager::Instance().SetMonitoringEnabled(true);
    return 0;
}

static int CmdPushConfig()
{
    if (!CommManager::Instance().IsConnected()) {
        wprintf(L"RansomShield: Not connected. Attempting to connect...\n");
        HRESULT hr = CommManager::Instance().Connect();
        if (FAILED(hr)) return 1;
    }

    if (!ConfigManager::Instance().PushToDriver()) {
        return 1;
    }

    return 0;
}

// ============================================================================
// SERVICE/DAEMON MODE
// ============================================================================

/*++
Routine Description:
    Runs the application in daemon mode. This is the default when no
    CLI arguments are provided. The application:
      1. Loads configuration from the registry.
      2. Connects to the driver.
      3. Pushes the configuration to the driver.
      4. Starts the notification listener.
      5. Enters a wait loop (could be a Windows Service main loop).

    In a production Windows Service, this would be called from the
    ServiceMain() callback after RegisterServiceCtrlHandler().
--*/
static int RunDaemonMode()
{
    wprintf(L"RansomShield: Starting in daemon mode...\n\n");

    //
    // Step 1: Initialize the event logger.
    //
    if (!EventLogger::Instance().Initialize()) {
        fwprintf(stderr, L"RansomShield: Warning: Event logger initialization failed.\n");
    }

    //
    // Step 2: Load configuration from the registry.
    //
    if (!ConfigManager::Instance().Initialize()) {
        fwprintf(stderr, L"RansomShield: Failed to load configuration. Using defaults.\n");
    }

    //
    // Step 3: Connect to the driver.
    //
    HRESULT hr = CommManager::Instance().Connect();
    if (FAILED(hr)) {
        EventLogger::Instance().LogWarning(L"Cannot connect to RansomShield driver. Retrying in 10 seconds...");

        //
        // Retry loop for daemon mode. The driver may not be loaded yet
        // if this service starts at boot time (the driver loads as part
        // of the filter manager initialization).
        //
        for (int attempt = 0; attempt < 12; attempt++) {  // 12 * 10s = 2 min
            Sleep(10000);
            hr = CommManager::Instance().Connect();
            if (SUCCEEDED(hr)) {
                break;
            }
        }

        if (FAILED(hr)) {
            EventLogger::Instance().LogError(L"Cannot connect to RansomShield driver after 2 minutes. Exiting.");
            return 1;
        }
    }

    //
    // Step 4: Push configuration and allowlist to the driver.
    //
    if (!ConfigManager::Instance().PushToDriver()) {
        EventLogger::Instance().LogWarning(L"Failed to push configuration to driver.");
    }

    //
    // Step 5: Start the notification listener.
    //
    // The listener callback dispatches to EventLogger::HandleNotification,
    // which logs events and displays alerts.
    //
    hr = CommManager::Instance().StartListener(
        [](const BYTE* data, DWORD dataSize) {
            EventLogger::Instance().HandleNotification(data, dataSize);
        }
    );

    if (FAILED(hr)) {
        EventLogger::Instance().LogError(L"Failed to start notification listener.");
        return 1;
    }

    EventLogger::Instance().LogInfo(L"RansomShield daemon is running. Listening for alerts...");

    wprintf(L"RansomShield: Daemon running. Press Ctrl+C to stop.\n\n");

    //
    // Step 6: Main wait loop.
    //
    // In a production Windows Service, this would be the service's
    // main loop that waits on the SCM's shutdown event. For a CLI
    // daemon mode, we simply wait for Ctrl+C (SIGINT).
    //
    // We use a large sleep interval and check IsConnected() to detect
    // if the driver disconnected unexpectedly.
    //
    while (CommManager::Instance().IsConnected()) {
        Sleep(5000);  // 5 second poll interval

        //
        // Periodic health check: Query the driver's config.
        // This also serves as a keep-alive to detect disconnections.
        //
        // We only do this every 60 seconds (12 * 5s) to avoid
        // unnecessary driver traffic.
        //
        static int pollCounter = 0;
        pollCounter++;
        if (pollCounter >= 12) {
            pollCounter = 0;

            RS_REPLY_CONFIG config;
            ZeroMemory(&config, sizeof(config));
            hr = CommManager::Instance().QueryConfig(config);
            if (FAILED(hr)) {
                EventLogger::Instance().LogWarning(L"Driver health check failed. Attempting reconnection...");
                //
                // Attempt reconnection.
                //
                CommManager::Instance().Disconnect();
                hr = CommManager::Instance().Connect();
                if (SUCCEEDED(hr)) {
                    EventLogger::Instance().LogInfo(L"Reconnected to driver.");
                    ConfigManager::Instance().PushToDriver();
                    CommManager::Instance().StartListener(
                        [](const BYTE* data, DWORD dataSize) {
                            EventLogger::Instance().HandleNotification(data, dataSize);
                        }
                    );
                }
            }
        }
    }

    EventLogger::Instance().LogInfo(L"RansomShield daemon shutting down.");
    CommManager::Instance().StopListener();
    CommManager::Instance().Disconnect();

    return 0;
}

// ============================================================================
// USAGE
// ============================================================================

static void PrintUsage()
{
    wprintf(L"\n");
    wprintf(L"RansomShield — Ransomware Protection Control Application\n");
    wprintf(L"═════════════════════════════════════════════════════════\n\n");
    wprintf(L"USAGE: RansomShield.exe [command] [options]\n\n");
    wprintf(L"COMMANDS:\n");
    wprintf(L"  (no args)                        Start in daemon mode (connect & listen)\n");
    wprintf(L"  --status                         Query current driver status\n");
    wprintf(L"  --set-threshold <count> <secs>   Set heuristic threshold\n");
    wprintf(L"  --add-exception <name>           Add process to allowlist\n");
    wprintf(L"  --remove-exception <name>        Remove process from allowlist\n");
    wprintf(L"  --list-exceptions                Display all allowlist entries\n");
    wprintf(L"  --unblock <pid>                  Unblock a previously blocked process\n");
    wprintf(L"  --list-blocked                   List all currently blocked PIDs\n");
    wprintf(L"  --pause                          Pause monitoring (stop blocking)\n");
    wprintf(L"  --resume                         Resume monitoring after pause\n");
    wprintf(L"  --push-config                    Push registry config to driver\n");
    wprintf(L"  --help                           Show this help message\n\n");
    wprintf(L"EXAMPLES:\n");
    wprintf(L"  RansomShield.exe --set-threshold 100 15\n");
    wprintf(L"  RansomShield.exe --add-exception code.exe\n");
    wprintf(L"  RansomShield.exe --unblock 4816\n");
    wprintf(L"  RansomShield.exe --status\n\n");
    wprintf(L"NOTE: This application requires Administrator privileges.\n");
    wprintf(L"      Run as Administrator or install as a Windows Service.\n\n");
}

// ============================================================================
// ENTRY POINT
// ============================================================================

int __cdecl wmain(int argc, wchar_t* argv[])
{
    //
    // Step 1: Check for Administrator privileges.
    //
    if (!IsElevated()) {
        fwprintf(stderr, L"\nRansomShield: ERROR - This application requires Administrator privileges.\n");
        fwprintf(stderr, L"Right-click and select 'Run as Administrator', or install as a Windows Service.\n\n");
        return 1;
    }

    //
    // Step 2: Parse CLI arguments.
    //
    if (argc < 2) {
        //
        // No arguments → daemon mode.
        //
        return RunDaemonMode();
    }

    std::wstring command = argv[1];

    //
    // Transform to lowercase for case-insensitive comparison.
    //
    std::transform(command.begin(), command.end(), command.begin(), ::towlower);

    if (command == L"--help" || command == L"-h" || command == L"/?") {
        PrintUsage();
        return 0;
    }

    //
    // For CLI commands, we need to initialize the config manager
    // (to read current values) and optionally connect to the driver.
    //
    ConfigManager::Instance().Initialize();

    if (command == L"--status") {
        return CmdStatus();
    }
    else if (command == L"--set-threshold") {
        return CmdSetThreshold(argc, argv);
    }
    else if (command == L"--add-exception") {
        if (argc < 3) {
            fwprintf(stderr, L"Usage: RansomShield.exe --add-exception <imageName>\n");
            return 1;
        }
        return CmdAddException(argv[2]);
    }
    else if (command == L"--remove-exception") {
        if (argc < 3) {
            fwprintf(stderr, L"Usage: RansomShield.exe --remove-exception <imageName>\n");
            return 1;
        }
        return CmdRemoveException(argv[2]);
    }
    else if (command == L"--list-exceptions") {
        return CmdListExceptions();
    }
    else if (command == L"--unblock") {
        if (argc < 3) {
            fwprintf(stderr, L"Usage: RansomShield.exe --unblock <pid>\n");
            return 1;
        }
        ULONG pid = static_cast<ULONG>(_wtoi(argv[2]));
        return CmdUnblock(pid);
    }
    else if (command == L"--list-blocked") {
        return CmdListBlocked();
    }
    else if (command == L"--pause") {
        return CmdPause();
    }
    else if (command == L"--resume") {
        return CmdResume();
    }
    else if (command == L"--push-config") {
        return CmdPushConfig();
    }
    else {
        fwprintf(stderr, L"RansomShield: Unknown command '%s'. Use --help for usage.\n", argv[1]);
        return 1;
    }
}
