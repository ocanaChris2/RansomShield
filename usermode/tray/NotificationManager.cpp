/*++
Module Name:
    NotificationManager.cpp

Abstract:
    Implementation of NotificationManager.
    See NotificationManager.h for the design overview.
--*/

#include "NotificationManager.h"
#include <strsafe.h>
#include <objbase.h>    // CoInitializeEx / CoCreateInstance / CoUninitialize
#include <taskschd.h>   // ITaskService, ITaskFolder, IRegisteredTask
#include <oleauto.h>    // SysAllocString / SysFreeString
#include <vector>

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

NotificationManager& NotificationManager::Instance() {
    static NotificationManager s;
    return s;
}

// ---------------------------------------------------------------------------
// Initialize / Shutdown
// ---------------------------------------------------------------------------

bool NotificationManager::Initialize(HINSTANCE hInst, HWND hwnd) {
    m_hInst = hInst;
    m_hwnd  = hwnd;

    ZeroMemory(&m_nid, sizeof(m_nid));
    m_nid.cbSize           = sizeof(m_nid);
    m_nid.hWnd             = hwnd;
    m_nid.uID              = 1;
    m_nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP;
    m_nid.uCallbackMessage = WM_TRAYNOTIFY;

    // Prefer the system Shield icon (UAC-style, recognisable as security).
    // Fall back to the generic application icon on failure.
    SHSTOCKICONINFO sii = {};
    sii.cbSize = sizeof(sii);
    if (SUCCEEDED(SHGetStockIconInfo(SIID_SHIELD, SHGSI_ICON | SHGSI_SMALLICON, &sii))) {
        m_nid.hIcon = sii.hIcon;
    } else {
        m_nid.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    }

    StringCchCopyW(m_nid.szTip, ARRAYSIZE(m_nid.szTip),
                   L"RansomShield — Connecting to driver...");

    AddTrayIcon();

    // Remove legacy HKCU Run entry that launched the tray without elevation.
    // The new mechanism uses a Task Scheduler task with HighestAvailable RunLevel.
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, L"RansomShieldTray");
            RegCloseKey(hKey);
        }
    }

    m_initialized = true;
    return true;
}

void NotificationManager::Shutdown() {
    if (m_initialized) {
        RemoveTrayIcon();
        m_initialized = false;
    }
}

// ---------------------------------------------------------------------------
// Tray icon helpers
// ---------------------------------------------------------------------------

void NotificationManager::AddTrayIcon() {
    Shell_NotifyIconW(NIM_ADD, &m_nid);

    // Switch to version 4 so LOWORD(lParam) in WM_TRAYNOTIFY is the event.
    NOTIFYICONDATAW nidVer = {};
    nidVer.cbSize   = sizeof(nidVer);
    nidVer.hWnd     = m_hwnd;
    nidVer.uID      = 1;
    nidVer.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &nidVer);
}

void NotificationManager::RemoveTrayIcon() {
    Shell_NotifyIconW(NIM_DELETE, &m_nid);
}

// ---------------------------------------------------------------------------
// Alert queue  (called from listener background thread)
// ---------------------------------------------------------------------------

void NotificationManager::QueueAlert(DWORD pid, const std::wstring& imageName, DWORD opCount) {
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_alertQueue.push({pid, imageName, opCount});
    }
    // Signal the main thread — no data crosses the message; it drains the queue.
    PostMessageW(m_hwnd, WM_RSBLOCKED, 0, 0);
}

bool NotificationManager::DrainAlert(RsAlertData& out) {
    std::lock_guard<std::mutex> lock(m_queueMutex);
    if (m_alertQueue.empty()) return false;
    out = std::move(m_alertQueue.front());
    m_alertQueue.pop();
    return true;
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

void NotificationManager::ShowRansomwareAlert(const RsAlertData& alert) {
    wchar_t body[512];
    StringCchPrintfW(body, ARRAYSIZE(body),
        L"Process BLOCKED\n"
        L"PID: %lu  |  %s\n"
        L"%lu file operations detected in time window",
        alert.pid, alert.imageName.c_str(), alert.opCount);

    ShowBalloon(L"Ransomware Detected — RansomShield", body, NIIF_WARNING);
}

void NotificationManager::ShowBalloon(const wchar_t* title, const wchar_t* msg, DWORD niifFlags) {
    NOTIFYICONDATAW nid = m_nid;
    nid.uFlags     |= NIF_INFO;
    nid.dwInfoFlags = niifFlags;
    StringCchCopyW(nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle), title);
    StringCchCopyW(nid.szInfo,      ARRAYSIZE(nid.szInfo),      msg);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

void NotificationManager::SetStatus(bool connected, bool paused) {
    m_connected = connected;
    m_paused    = paused;

    const wchar_t* tip;
    if (!connected)  tip = L"RansomShield — Driver offline (retrying...)";
    else if (paused) tip = L"RansomShield — Monitoring PAUSED";
    else             tip = L"RansomShield — Monitoring ACTIVE";

    StringCchCopyW(m_nid.szTip, ARRAYSIZE(m_nid.szTip), tip);
    Shell_NotifyIconW(NIM_MODIFY, &m_nid);
}

// ---------------------------------------------------------------------------
// Tray interaction
// ---------------------------------------------------------------------------

void NotificationManager::HandleTrayMessage(LPARAM lParam) {
    // With NOTIFYICON_VERSION_4, LOWORD(lParam) is the mouse/keyboard event.
    switch (LOWORD(lParam)) {
    case WM_CONTEXTMENU:
    case WM_RBUTTONUP:
        ShowContextMenu();
        break;
    case WM_LBUTTONDBLCLK:
        // Double-click → show status (same as the menu item)
        PostMessageW(m_hwnd, WM_COMMAND, IDM_STATUS, 0);
        break;
    }
}

void NotificationManager::ShowContextMenu() {
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu) return;

    // Non-clickable header row
    AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 0, L"RansomShield Protection");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    // Status and pause/resume are greyed when the driver is offline
    UINT connFlag = m_connected ? MF_STRING : (MF_STRING | MF_GRAYED);
    AppendMenuW(hMenu, connFlag, IDM_STATUS,
                m_connected ? L"Driver Status" : L"Driver Status  (offline)");

    AppendMenuW(hMenu, connFlag, IDM_TOGGLEPAUSE,
                m_paused ? L"Resume Monitoring" : L"Pause Monitoring");

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, IDM_OPENLOG, L"Open Log File");

    UINT autoFlags = MF_STRING | (IsAutoStartEnabled() ? MF_CHECKED : MF_UNCHECKED);
    AppendMenuW(hMenu, autoFlags, IDM_AUTOSTART, L"Start with Windows");

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, IDM_EXIT, L"Exit");

    // Required so the menu closes when clicking outside it
    SetForegroundWindow(m_hwnd);

    POINT pt;
    GetCursorPos(&pt);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_RIGHTALIGN, pt.x, pt.y, 0, m_hwnd, nullptr);

    // Force the menu to close (see Raymond Chen's "Q141927" note)
    PostMessageW(m_hwnd, WM_NULL, 0, 0);

    DestroyMenu(hMenu);
}

// ---------------------------------------------------------------------------
// Auto-start via Windows Task Scheduler (runs elevated at logon)
// ---------------------------------------------------------------------------

static constexpr wchar_t TASK_NAME[] = L"RansomShieldTray";

// Returns DOMAIN\Username for the current process token (used in task XML).
static std::wstring GetCurrentUserSamName() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return {};

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    std::vector<BYTE> buf(needed);
    BOOL ok = GetTokenInformation(hToken, TokenUser, buf.data(), needed, &needed);
    CloseHandle(hToken);
    if (!ok) return {};

    const auto* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
    wchar_t name[256] = {}, domain[256] = {};
    DWORD nameLen = ARRAYSIZE(name), domainLen = ARRAYSIZE(domain);
    SID_NAME_USE use = SidTypeUnknown;
    if (!LookupAccountSidW(nullptr, tu->User.Sid, name, &nameLen, domain, &domainLen, &use))
        return {};
    return std::wstring(domain) + L"\\" + name;
}

// Connects to the local Task Scheduler service. Caller releases *ppSvc.
static HRESULT ConnectTaskService(ITaskService** ppSvc) {
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_ITaskService, reinterpret_cast<void**>(ppSvc));
    if (FAILED(hr)) return hr;
    VARIANT empty = {};
    return (*ppSvc)->Connect(empty, empty, empty, empty);
}

bool NotificationManager::IsAutoStartEnabled() const {
    HRESULT hrCo = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    ITaskService* svc = nullptr;
    bool found = false;

    if (SUCCEEDED(ConnectTaskService(&svc))) {
        ITaskFolder* folder = nullptr;
        BSTR root = SysAllocString(L"\\");
        if (SUCCEEDED(svc->GetFolder(root, &folder))) {
            IRegisteredTask* task = nullptr;
            BSTR tname = SysAllocString(TASK_NAME);
            found = SUCCEEDED(folder->GetTask(tname, &task));
            SysFreeString(tname);
            if (task) task->Release();
            folder->Release();
        }
        SysFreeString(root);
        svc->Release();
    }

    if (hrCo == S_OK) CoUninitialize();
    return found;
}

void NotificationManager::ToggleAutoStart() {
    bool enable = !IsAutoStartEnabled();
    HRESULT hrCo = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    ITaskService* svc = nullptr;
    if (FAILED(ConnectTaskService(&svc))) {
        if (hrCo == S_OK) CoUninitialize();
        return;
    }

    ITaskFolder* folder = nullptr;
    BSTR root = SysAllocString(L"\\");
    HRESULT hr = svc->GetFolder(root, &folder);
    SysFreeString(root);
    svc->Release();
    if (FAILED(hr)) {
        if (hrCo == S_OK) CoUninitialize();
        return;
    }

    BSTR taskName = SysAllocString(TASK_NAME);

    if (enable) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        std::wstring user = GetCurrentUserSamName();
        if (user.empty()) {
            SysFreeString(taskName);
            folder->Release();
            if (hrCo == S_OK) CoUninitialize();
            return;
        }

        // Logon trigger + HighestAvailable so the tray starts elevated automatically.
        wchar_t xml[4096] = {};
        StringCchPrintfW(xml, ARRAYSIZE(xml),
            L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
            L"<Task version=\"1.2\""
            L" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            L"<Triggers>"
            L"<LogonTrigger><UserId>%s</UserId></LogonTrigger>"
            L"</Triggers>"
            L"<Principals><Principal id=\"Author\">"
            L"<UserId>%s</UserId>"
            L"<LogonType>InteractiveToken</LogonType>"
            L"<RunLevel>HighestAvailable</RunLevel>"
            L"</Principal></Principals>"
            L"<Settings>"
            L"<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
            L"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
            L"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
            L"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"
            L"</Settings>"
            L"<Actions Context=\"Author\">"
            L"<Exec><Command>%s</Command></Exec>"
            L"</Actions>"
            L"</Task>",
            user.c_str(), user.c_str(), exePath);

        VARIANT vtEmpty = {};
        BSTR xmlStr = SysAllocString(xml);
        IRegisteredTask* task = nullptr;
        folder->RegisterTask(taskName, xmlStr,
                             TASK_CREATE_OR_UPDATE,
                             vtEmpty, vtEmpty,
                             TASK_LOGON_INTERACTIVE_TOKEN,
                             vtEmpty, &task);
        SysFreeString(xmlStr);
        if (task) task->Release();
    } else {
        folder->DeleteTask(taskName, 0);
    }

    SysFreeString(taskName);
    folder->Release();
    if (hrCo == S_OK) CoUninitialize();
}
