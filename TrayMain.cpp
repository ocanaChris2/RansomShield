/*++
Module Name:
    TrayMain.cpp

Abstract:
    Entry point for RansomShieldTray.exe — a Windows GUI (no console)
    background agent that:

      1. Connects to the RansomShield minifilter driver.
      2. Receives push notifications (RsNotifyBlockedPid) on a background
         listener thread and converts them to Windows balloon-tip alerts.
      3. Exposes a system-tray icon with a right-click context menu for
         basic control (pause / resume, view status, toggle auto-start).
      4. Retries the driver connection automatically every 5 seconds if
         the driver is not yet loaded.
      5. Enforces a single running instance via a named mutex.

    This executable is a Windows-subsystem application (SubSystem = Windows,
    no console window). All stdin/stdout/stderr calls made by shared
    modules (EventLogger prints) are silently discarded.

    Architecture note:
    The driver communication port accepts only ONE client at a time.
    While this tray agent is running it holds that connection.
    Run RansomShieldClient.exe CLI commands only after stopping the tray
    agent, or interact with the driver through the tray menu.

Author:
    RansomShield Development
--*/

#include <Windows.h>
#include <shellapi.h>
#include <strsafe.h>

#include "SharedDefs.h"
#include "CommManager.h"
#include "ConfigManager.h"
#include "EventLogger.h"
#include "NotificationManager.h"

// ============================================================================
// Constants
// ============================================================================

static constexpr UINT       ID_TIMER_HEALTH = 1;
static constexpr UINT       HEALTH_INTERVAL_MS = 5000;   // 5 s poll
static constexpr int        HEALTH_TICKS_PER_QUERY = 12; // 12 * 5 s = 60 s

static constexpr wchar_t    WINDOW_CLASS[]  = L"RansomShieldTrayWnd";
static constexpr wchar_t    MUTEX_NAME[]    = L"Global\\RansomShieldTrayMutex_3F7A";

// ============================================================================
// Module-level state
// ============================================================================

static int s_healthTick = 0;

// ============================================================================
// Privilege check (same logic as RansomShieldClient)
// ============================================================================

static bool IsElevated() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminSid = nullptr;
    if (!AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminSid)) {
        return false;
    }
    CheckTokenMembership(nullptr, adminSid, &isAdmin);
    FreeSid(adminSid);
    return isAdmin != FALSE;
}

// ============================================================================
// Driver listener callback  (called from CommManager's background thread)
// ============================================================================

static void ListenerCallback(const BYTE* data, DWORD dataSize) {
    if (dataSize < sizeof(RS_MESSAGE_HEADER)) return;

    const RS_MESSAGE_HEADER* hdr = reinterpret_cast<const RS_MESSAGE_HEADER*>(data);

    if (hdr->MessageType == RsNotifyBlockedPid &&
        dataSize >= sizeof(RS_NOTIFICATION_BLOCKED_PID)) {

        const RS_NOTIFICATION_BLOCKED_PID* n =
            reinterpret_cast<const RS_NOTIFICATION_BLOCKED_PID*>(data);

        // Queue balloon for the main thread and write to the event/file log.
        NotificationManager::Instance().QueueAlert(
            n->ProcessId, n->ImageName, n->OperationCount);

        EventLogger::Instance().LogRansomwareDetected(
            n->ProcessId, n->ImageName, n->OperationCount);
    }
    // Config / allowlist acknowledgements are informational; log only.
    else if (hdr->MessageType == RsNotifyConfigUpdated &&
             dataSize >= sizeof(RS_NOTIFICATION_CONFIG_UPDATED)) {

        const RS_NOTIFICATION_CONFIG_UPDATED* n =
            reinterpret_cast<const RS_NOTIFICATION_CONFIG_UPDATED*>(data);
        EventLogger::Instance().LogConfigChanged(
            n->FileCountThreshold,
            n->TimeWindowSeconds,
            n->MonitoringEnabled ? true : false);
    }
}

// ============================================================================
// Helper: (re)start the CommManager listener with our callback
// ============================================================================

static void StartListening() {
    CommManager::Instance().StartListener(ListenerCallback);
}

// ============================================================================
// WM_COMMAND handlers
// ============================================================================

static void ShowStatusDialog(HWND hwnd) {
    RS_REPLY_CONFIG cfg = {};
    if (FAILED(CommManager::Instance().QueryConfig(cfg))) {
        MessageBoxW(hwnd,
            L"Could not retrieve driver status.\n"
            L"The driver may have disconnected.",
            L"RansomShield", MB_OK | MB_ICONWARNING);
        return;
    }

    wchar_t body[512];
    StringCchPrintfW(body, ARRAYSIZE(body),
        L"Status:        %s\n"
        L"Threshold:     %lu files / %lu seconds\n"
        L"Tracked PIDs:  %lu\n"
        L"Blocked PIDs:  %lu",
        cfg.MonitoringEnabled ? L"ACTIVE" : L"PAUSED",
        cfg.FileCountThreshold, cfg.TimeWindowSeconds,
        cfg.TrackedPidCount, cfg.BlockedPidCount);

    MessageBoxW(hwnd, body, L"RansomShield — Driver Status",
                MB_OK | MB_ICONINFORMATION);
}

static void OpenLogFile() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    wchar_t* lastSlash = wcsrchr(exePath, L'\\');
    if (lastSlash) {
        StringCchCopyW(lastSlash + 1,
                       MAX_PATH - static_cast<DWORD>(lastSlash - exePath + 1),
                       L"RansomShield.log");
    }

    ShellExecuteW(nullptr, L"open", exePath, nullptr, nullptr, SW_SHOW);
}

static void TogglePauseMonitoring(HWND hwnd) {
    RS_REPLY_CONFIG cfg = {};
    if (FAILED(CommManager::Instance().QueryConfig(cfg))) {
        MessageBoxW(hwnd, L"Could not query driver state.",
                    L"RansomShield", MB_OK | MB_ICONWARNING);
        return;
    }

    bool currentlyMonitoring = (cfg.MonitoringEnabled != FALSE);
    HRESULT hr;

    if (currentlyMonitoring) {
        hr = CommManager::Instance().PauseMonitoring();
        if (SUCCEEDED(hr)) {
            NotificationManager::Instance().SetStatus(true, true);
            ConfigManager::Instance().SetMonitoringEnabled(false);
        }
    } else {
        hr = CommManager::Instance().ResumeMonitoring();
        if (SUCCEEDED(hr)) {
            NotificationManager::Instance().SetStatus(true, false);
            ConfigManager::Instance().SetMonitoringEnabled(true);
        }
    }
}

// ============================================================================
// Window procedure
// ============================================================================

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {

    // ── Tray icon notification ─────────────────────────────────────────────
    case NotificationManager::WM_TRAYNOTIFY:
        NotificationManager::Instance().HandleTrayMessage(lp);
        return 0;

    // ── Blocked-PID alert from listener thread ─────────────────────────────
    case NotificationManager::WM_RSBLOCKED: {
        RsAlertData alert;
        while (NotificationManager::Instance().DrainAlert(alert)) {
            NotificationManager::Instance().ShowRansomwareAlert(alert);
        }
        return 0;
    }

    // ── Context-menu commands ──────────────────────────────────────────────
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case NotificationManager::IDM_STATUS:
            ShowStatusDialog(hwnd);
            break;
        case NotificationManager::IDM_TOGGLEPAUSE:
            TogglePauseMonitoring(hwnd);
            break;
        case NotificationManager::IDM_OPENLOG:
            OpenLogFile();
            break;
        case NotificationManager::IDM_AUTOSTART:
            NotificationManager::Instance().ToggleAutoStart();
            break;
        case NotificationManager::IDM_EXIT:
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    // ── Health-check / reconnect timer ────────────────────────────────────
    case WM_TIMER:
        if (wp == ID_TIMER_HEALTH) {
            bool connected = CommManager::Instance().IsConnected();

            if (!connected) {
                // Attempt reconnection every tick (5 s) until we succeed.
                HRESULT hr = CommManager::Instance().Connect();
                if (SUCCEEDED(hr)) {
                    ConfigManager::Instance().PushToDriver();
                    StartListening();
                    NotificationManager::Instance().SetStatus(true, false);
                    EventLogger::Instance().LogInfo(
                        L"RansomShield tray agent reconnected to driver.");
                    s_healthTick = 0;
                }
                // If still failing, SetStatus keeps the "offline" tooltip.
            } else {
                // Periodic deep health check (every 60 s)
                s_healthTick++;
                if (s_healthTick >= HEALTH_TICKS_PER_QUERY) {
                    s_healthTick = 0;
                    RS_REPLY_CONFIG cfg = {};
                    if (FAILED(CommManager::Instance().QueryConfig(cfg))) {
                        // Driver has gone away
                        CommManager::Instance().Disconnect();
                        NotificationManager::Instance().SetStatus(false, false);
                        EventLogger::Instance().LogWarning(
                            L"RansomShield driver connection lost. Retrying...");
                    }
                }
            }
        }
        return 0;

    // ── Shutdown ──────────────────────────────────────────────────────────
    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER_HEALTH);
        NotificationManager::Instance().Shutdown();
        CommManager::Instance().StopListener();
        CommManager::Instance().Disconnect();
        EventLogger::Instance().LogInfo(L"RansomShield tray agent stopped.");
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ============================================================================
// Entry point
// ============================================================================

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrev*/,
                    LPWSTR /*lpCmdLine*/, int /*nCmdShow*/)
{
    // ── Single-instance guard ──────────────────────────────────────────────
    HANDLE hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0;
    }

    // ── Privilege check ────────────────────────────────────────────────────
    if (!IsElevated()) {
        MessageBoxW(nullptr,
            L"RansomShield requires Administrator privileges.\n\n"
            L"Right-click the executable and select 'Run as administrator'.",
            L"RansomShield", MB_OK | MB_ICONERROR);
        CloseHandle(hMutex);
        return 1;
    }

    // ── Register hidden message window class ──────────────────────────────
    WNDCLASSEXW wc   = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = WINDOW_CLASS;
    RegisterClassExW(&wc);

    // Create an invisible 1×1 window. Its sole purpose is to own the
    // tray icon and serve as the target for PostMessage / SendMessage.
    HWND hwnd = CreateWindowExW(
        0, WINDOW_CLASS, L"RansomShield",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1, 1,
        nullptr, nullptr, hInstance, nullptr);

    // ── Initialise subsystems ──────────────────────────────────────────────
    EventLogger::Instance().Initialize();
    ConfigManager::Instance().Initialize();
    NotificationManager::Instance().Initialize(hInstance, hwnd);

    // ── Connect to driver (best-effort; timer retries on failure) ─────────
    HRESULT hr = CommManager::Instance().Connect();
    if (SUCCEEDED(hr)) {
        ConfigManager::Instance().PushToDriver();
        StartListening();
        NotificationManager::Instance().SetStatus(true, false);
        EventLogger::Instance().LogInfo(L"RansomShield tray agent started.");
    } else {
        NotificationManager::Instance().SetStatus(false, false);
        // The health-check timer will retry every 5 s.
    }

    // ── Health-check / reconnect timer ────────────────────────────────────
    SetTimer(hwnd, ID_TIMER_HEALTH, HEALTH_INTERVAL_MS, nullptr);

    // ── Message loop ──────────────────────────────────────────────────────
    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(hMutex);
    return static_cast<int>(msg.wParam);
}
