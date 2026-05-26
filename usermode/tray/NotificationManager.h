/*++
Module Name:
    NotificationManager.h

Abstract:
    System-tray icon and balloon-tip notification manager for the
    RansomShield background tray agent (RansomShieldTray.exe).

    Responsibilities:
      - Add / remove a system-tray icon via Shell_NotifyIcon.
      - Show Windows balloon-tip notifications when ransomware is blocked.
      - Present a right-click context menu (status, pause/resume, log, auto-start, exit).
      - Maintain a thread-safe queue so the CommManager listener thread
        can post alerts that are consumed and displayed on the main (UI) thread.

    Thread safety:
      - QueueAlert() is safe to call from any thread.
      - All other public methods must be called from the main (message-pump) thread.

Author:
    RansomShield Development
--*/

#pragma once

#include <Windows.h>
#include <shellapi.h>
#include <string>
#include <queue>
#include <mutex>

// ---------------------------------------------------------------------------
// Alert payload posted from the listener thread to the main thread.
// ---------------------------------------------------------------------------
struct RsAlertData {
    DWORD        pid;
    std::wstring imageName;
    DWORD        opCount;
};

// ---------------------------------------------------------------------------
// NotificationManager — singleton
// ---------------------------------------------------------------------------
class NotificationManager {
public:
    static NotificationManager& Instance();

    // Custom window messages
    static constexpr UINT WM_TRAYNOTIFY = WM_USER + 1;  // Shell_NotifyIcon callback
    static constexpr UINT WM_RSBLOCKED  = WM_USER + 2;  // Signal: drain alert queue

    // Context-menu command IDs
    static constexpr UINT IDM_STATUS      = 100;
    static constexpr UINT IDM_TOGGLEPAUSE = 101;
    static constexpr UINT IDM_OPENLOG     = 102;
    static constexpr UINT IDM_AUTOSTART   = 103;
    static constexpr UINT IDM_EXIT        = 109;

    // ── Lifecycle ──────────────────────────────────────────────────────────

    bool Initialize(HINSTANCE hInst, HWND hwnd);
    void Shutdown();

    // ── Alert queue (thread-safe) ──────────────────────────────────────────

    // Called from the listener background thread.
    // Pushes an alert and posts WM_RSBLOCKED to the message window.
    void QueueAlert(DWORD pid, const std::wstring& imageName, DWORD opCount);

    // Called from the main thread via WM_RSBLOCKED.
    // Pops one alert; returns false when the queue is empty.
    bool DrainAlert(RsAlertData& out);

    // ── Notifications ──────────────────────────────────────────────────────

    void ShowRansomwareAlert(const RsAlertData& alert);

    // Update tooltip text to reflect connection / pause state.
    void SetStatus(bool connected, bool paused);

    // ── Tray interaction ──────────────────────────────────────────────────

    // Call from WndProc when msg == WM_TRAYNOTIFY.
    void HandleTrayMessage(LPARAM lParam);

    // Show the right-click context menu at the current cursor position.
    void ShowContextMenu();

    // Toggle the "Start with Windows" registry entry for this executable.
    void ToggleAutoStart();
    bool IsAutoStartEnabled() const;

private:
    NotificationManager() = default;
    NotificationManager(const NotificationManager&) = delete;
    NotificationManager& operator=(const NotificationManager&) = delete;

    void AddTrayIcon();
    void RemoveTrayIcon();
    void ShowBalloon(const wchar_t* title, const wchar_t* msg, DWORD niifFlags);

    HINSTANCE       m_hInst       = nullptr;
    HWND            m_hwnd        = nullptr;
    NOTIFYICONDATAW m_nid         = {};
    bool            m_initialized = false;
    bool            m_paused      = false;
    bool            m_connected   = false;

    std::queue<RsAlertData> m_alertQueue;
    std::mutex              m_queueMutex;
};
