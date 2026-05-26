/*++
Module Name:
    ConfigManager.cpp

Abstract:
    Implementation of the Configuration and Allowlist Manager.
    See ConfigManager.h for design rationale and registry layout.

    REGISTRY API NOTES:

    The Windows Registry API (advapi32.dll) provides persistent key-value
    storage. Key functions used here:

    - RegCreateKeyExW: Creates a key if it doesn't exist, or opens it.
      We use this instead of RegOpenKeyExW to handle first-run scenarios.

    - RegSetValueExW: Writes a value under an open key.
      For REG_DWORD: passes a DWORD pointer and sizeof(DWORD).
      For REG_SZ: passes a wide string buffer and byte count (including null).

    - RegQueryValueExW: Reads a value from an open key.
      Returns ERROR_FILE_NOT_FOUND if the value doesn't exist.

    - RegDeleteValueW: Deletes a named value from a key.

    - RegCloseKey: Closes an open key handle.

    All registry operations require appropriate access rights. The keys
    under HKLM\SYSTEM\CurrentControlSet\Services\ require Administrator
    or SYSTEM privileges to write, which is appropriate since our
    application runs elevated.

    ERROR HANDLING PHILOSOPHY:
    - If a registry read fails (e.g., value doesn't exist), we use the
      default value from SharedDefs.h. This ensures the application can
      always start, even with a corrupt or missing registry.
    - If a registry write fails, we log the error but don't crash. The
      configuration is still valid in memory; it just won't persist
      across reboots.
    - We never leave registry keys open longer than necessary for
      bulk operations (like loading the entire allowlist).

Author:
    RansomShield Development
--*/

#include "ConfigManager.h"
#include <algorithm>
#include <cwchar>

ConfigManager::ConfigManager(const wchar_t* registryBasePath)
    : m_fileCountThreshold(RS_DEFAULT_FILE_COUNT_THRESHOLD)
    , m_timeWindowSeconds(RS_DEFAULT_TIME_WINDOW_SECONDS)
    , m_monitoringEnabled(RS_DEFAULT_MONITORING_ENABLED)
    , m_initialized(false)
    , m_hConfigKey(NULL)
    , m_hAllowlistKey(NULL)
    , m_registryBasePath(registryBasePath)
{
}

ConfigManager::~ConfigManager()
{
    if (m_hConfigKey) {
        RegCloseKey(m_hConfigKey);
        m_hConfigKey = NULL;
    }
    if (m_hAllowlistKey) {
        RegCloseKey(m_hAllowlistKey);
        m_hAllowlistKey = NULL;
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool ConfigManager::Initialize()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized) {
        return true;
    }

    //
    // Open (or create) the Config and Allowlist registry keys.
    // We keep these keys open for the lifetime of the application
    // to avoid repeated open/close overhead.
    //
    // RegCreateKeyExW creates the key if it doesn't exist. This handles
    // first-run scenarios where the keys haven't been created yet.
    //
    // KEY_ALL_ACCESS gives us read/write/create permissions.
    // This requires the process to be running as Administrator or SYSTEM.
    //
    std::wstring configPath    = m_registryBasePath + L"\\" + RS_REGISTRY_CONFIG_KEY;
    std::wstring allowlistPath = m_registryBasePath + L"\\" + RS_REGISTRY_ALLOWLIST_KEY;

    if (!OpenOrCreateKey(HKEY_LOCAL_MACHINE, configPath.c_str(), &m_hConfigKey)) {
        fwprintf(stderr, L"RansomShield: Failed to open/create Config registry key.\n");
        return false;
    }

    if (!OpenOrCreateKey(HKEY_LOCAL_MACHINE, allowlistPath.c_str(), &m_hAllowlistKey)) {
        fwprintf(stderr, L"RansomShield: Failed to open/create Allowlist registry key.\n");
        return false;
    }

    //
    // Load settings from the registry. Missing values use defaults.
    //
    m_fileCountThreshold = ReadDWord(m_hConfigKey, RS_REGVAL_THRESHOLD, RS_DEFAULT_FILE_COUNT_THRESHOLD);
    m_timeWindowSeconds = ReadDWord(m_hConfigKey, RS_REGVAL_TIMEWINDOW, RS_DEFAULT_TIME_WINDOW_SECONDS);
    m_monitoringEnabled = (ReadDWord(m_hConfigKey, RS_REGVAL_MONITORING, RS_DEFAULT_MONITORING_ENABLED) != 0);

    //
    // Load the allowlist from the registry.
    // Entries are stored as Entry00, Entry01, ..., EntryNN.
    // We read sequentially until we find a missing entry.
    //
    m_allowlist.clear();
    for (ULONG i = 0; i < RS_MAX_ALLOWLIST_ENTRIES; i++) {
        WCHAR valueName[16];
        swprintf_s(valueName, _countof(valueName), L"%s%02lu", RS_REGVAL_ENTRY_PREFIX, i);

        WCHAR data[RS_MAX_ALLOWLIST_NAME_LEN] = {0};
        DWORD dataSize = sizeof(data);
        DWORD type = 0;

        LONG result = RegQueryValueExW(
            m_hAllowlistKey,
            valueName,
            NULL,           // lpReserved (must be NULL)
            &type,          // [out] Type of data
            (LPBYTE)data,   // [out] Data buffer
            &dataSize       // [in/out] Size of data buffer
        );

        if (result != ERROR_SUCCESS || type != REG_SZ) {
            //
            // Entry doesn't exist or is the wrong type. We've reached
            // the end of the list (entries are stored sequentially).
            //
            break;
        }

        m_allowlist.push_back(std::wstring(data));
    }

    wprintf(L"RansomShield: Configuration loaded from registry.\n");
    wprintf(L"  Threshold: %lu files in %lu seconds\n", m_fileCountThreshold, m_timeWindowSeconds);
    wprintf(L"  Monitoring: %s\n", m_monitoringEnabled ? L"Enabled" : L"Disabled");
    wprintf(L"  Allowlist: %zu entries\n", m_allowlist.size());

    m_initialized = true;
    return true;
}

// ============================================================================
// CONFIGURATION GETTERS/SETTERS
// ============================================================================

ULONG ConfigManager::GetFileCountThreshold() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_fileCountThreshold;
}

void ConfigManager::SetFileCountThreshold(ULONG threshold)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_fileCountThreshold = threshold;
    }
    SaveToRegistry();
}

ULONG ConfigManager::GetTimeWindowSeconds() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_timeWindowSeconds;
}

void ConfigManager::SetTimeWindowSeconds(ULONG seconds)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_timeWindowSeconds = seconds;
    }
    SaveToRegistry();
}

bool ConfigManager::IsMonitoringEnabled() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_monitoringEnabled;
}

void ConfigManager::SetMonitoringEnabled(bool enabled)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_monitoringEnabled = enabled;
    }
    SaveToRegistry();
}

// ============================================================================
// ALLOWLIST MANAGEMENT
// ============================================================================

bool ConfigManager::AddException(const std::wstring& imageName)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    //
    // Check if the entry already exists (case-insensitive).
    // Windows file names are case-insensitive, so two entries that
    // differ only in case would be ambiguous.
    //
    for (const auto& entry : m_allowlist) {
        if (_wcsicmp(entry.c_str(), imageName.c_str()) == 0) {
            wprintf(L"RansomShield: '%s' is already in the allowlist.\n", imageName.c_str());
            return false;
        }
    }

    //
    // Check if the list is full.
    //
    if (m_allowlist.size() >= RS_MAX_ALLOWLIST_ENTRIES) {
        fwprintf(stderr, L"RansomShield: Allowlist is full (%d entries max).\n", RS_MAX_ALLOWLIST_ENTRIES);
        return false;
    }

    m_allowlist.push_back(imageName);

    wprintf(L"RansomShield: Added '%s' to allowlist.\n", imageName.c_str());

    return true;
}

bool ConfigManager::RemoveException(const std::wstring& imageName)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto it = m_allowlist.begin(); it != m_allowlist.end(); ++it) {
        if (_wcsicmp(it->c_str(), imageName.c_str()) == 0) {
            m_allowlist.erase(it);
            wprintf(L"RansomShield: Removed '%s' from allowlist.\n", imageName.c_str());
            return true;
        }
    }

    wprintf(L"RansomShield: '%s' not found in allowlist.\n", imageName.c_str());
    return false;
}

std::vector<std::wstring> ConfigManager::GetExceptions() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_allowlist;  // Returns a copy
}

bool ConfigManager::IsException(const std::wstring& imageName) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& entry : m_allowlist) {
        if (_wcsicmp(entry.c_str(), imageName.c_str()) == 0) {
            return true;
        }
    }

    return false;
}

void ConfigManager::ClearExceptions()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_allowlist.clear();
    wprintf(L"RansomShield: Allowlist cleared.\n");
}

// ============================================================================
// PERSISTENCE
// ============================================================================

bool ConfigManager::SaveToRegistry()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    bool success = true;

    //
    // Save configuration values.
    //
    if (!WriteDWord(m_hConfigKey, RS_REGVAL_THRESHOLD, m_fileCountThreshold)) {
        fwprintf(stderr, L"RansomShield: Failed to save FileCountThreshold.\n");
        success = false;
    }

    if (!WriteDWord(m_hConfigKey, RS_REGVAL_TIMEWINDOW, m_timeWindowSeconds)) {
        fwprintf(stderr, L"RansomShield: Failed to save TimeWindowSeconds.\n");
        success = false;
    }

    if (!WriteDWord(m_hConfigKey, RS_REGVAL_MONITORING, m_monitoringEnabled ? 1 : 0)) {
        fwprintf(stderr, L"RansomShield: Failed to save MonitoringEnabled.\n");
        success = false;
    }

    if (!WriteDWord(m_hConfigKey, RS_REGVAL_VERSION, RS_PROTOCOL_VERSION)) {
        fwprintf(stderr, L"RansomShield: Failed to save ProtocolVersion.\n");
        success = false;
    }

    //
    // Save allowlist entries.
    // Strategy: Delete all existing EntryXX values, then write new ones.
    // This avoids stale entries when items are removed from the list.
    //
    // First, delete all existing EntryXX values.
    //
    for (ULONG i = 0; i < RS_MAX_ALLOWLIST_ENTRIES; i++) {
        WCHAR valueName[16];
        swprintf_s(valueName, _countof(valueName), L"%s%02lu", RS_REGVAL_ENTRY_PREFIX, i);

        LONG result = RegDeleteValueW(m_hAllowlistKey, valueName);

        if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
            //
            // An unexpected error occurred. Continue anyway.
            //
            fwprintf(stderr, L"RansomShield: Warning: Failed to delete %s (error %ld).\n",
                     valueName, result);
        }

        //
        // Optimization: Once we hit a missing entry, all subsequent
        // entries should also be missing, so we can stop early.
        // But to be safe (in case of gaps from manual edits), we
        // continue until we've checked enough entries.
        //
        // Actually, for correctness, we should check all possible
        // entries. The cost is minimal (up to 128 RegDeleteValue calls).
        //
    }

    //
    // Write the new allowlist entries.
    //
    for (size_t i = 0; i < m_allowlist.size(); i++) {
        WCHAR valueName[16];
        swprintf_s(valueName, _countof(valueName), L"%s%02zu", RS_REGVAL_ENTRY_PREFIX, i);

        //
        // RegSetValueExW with REG_SZ requires the data to be a
        // null-terminated wide string. The dataSize must include
        // the null terminator in the byte count.
        //
        const std::wstring& entry = m_allowlist[i];
        DWORD dataSize = static_cast<DWORD>((entry.length() + 1) * sizeof(WCHAR));

        LONG result = RegSetValueExW(
            m_hAllowlistKey,
            valueName,
            0,                  // Reserved (must be 0)
            REG_SZ,
            reinterpret_cast<const BYTE*>(entry.c_str()),
            dataSize
        );

        if (result != ERROR_SUCCESS) {
            fwprintf(stderr, L"RansomShield: Failed to write %s (error %ld).\n",
                     valueName, result);
            success = false;
        }
    }

    if (success) {
        wprintf(L"RansomShield: Configuration saved to registry.\n");
    }

    return success;
}

bool ConfigManager::LoadFromRegistry()
{
    //
    // Re-read all values from the registry. This is essentially the
    // same logic as Initialize() but can be called at any time to
    // reload (e.g., after an external tool modifies the registry).
    //
    std::lock_guard<std::mutex> lock(m_mutex);

    m_fileCountThreshold = ReadDWord(m_hConfigKey, RS_REGVAL_THRESHOLD, RS_DEFAULT_FILE_COUNT_THRESHOLD);
    m_timeWindowSeconds = ReadDWord(m_hConfigKey, RS_REGVAL_TIMEWINDOW, RS_DEFAULT_TIME_WINDOW_SECONDS);
    m_monitoringEnabled = (ReadDWord(m_hConfigKey, RS_REGVAL_MONITORING, RS_DEFAULT_MONITORING_ENABLED) != 0);

    //
    // Reload the allowlist.
    //
    m_allowlist.clear();
    for (ULONG i = 0; i < RS_MAX_ALLOWLIST_ENTRIES; i++) {
        WCHAR valueName[16];
        swprintf_s(valueName, _countof(valueName), L"%s%02lu", RS_REGVAL_ENTRY_PREFIX, i);

        WCHAR data[RS_MAX_ALLOWLIST_NAME_LEN] = {0};
        DWORD dataSize = sizeof(data);
        DWORD type = 0;

        LONG result = RegQueryValueExW(m_hAllowlistKey, valueName, NULL, &type, (LPBYTE)data, &dataSize);

        if (result != ERROR_SUCCESS || type != REG_SZ) {
            break;
        }

        m_allowlist.push_back(std::wstring(data));
    }

    wprintf(L"RansomShield: Configuration reloaded from registry.\n");
    return true;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

bool ConfigManager::OpenOrCreateKey(
    _In_ HKEY hRootKey,
    _In_ const wchar_t* subKey,
    _Out_ PHKEY phKey
) const
{
    DWORD disposition = 0;

    //
    // RegCreateKeyExW creates the key if it doesn't exist, or opens
    // it if it does. The disposition parameter tells us which happened:
    //   REG_CREATED_NEW_KEY     = key was created
    //   REG_OPENED_EXISTING_KEY = key already existed
    //
    LONG result = RegCreateKeyExW(
        hRootKey,
        subKey,
        0,                  // Reserved (must be 0)
        NULL,               // lpClass (unused)
        REG_OPTION_NON_VOLATILE,  // Persist across reboots
        KEY_ALL_ACCESS,     // Full read/write access
        NULL,               // lpSecurityAttributes (inherit from parent)
        phKey,
        &disposition
    );

    if (result != ERROR_SUCCESS) {
        fwprintf(stderr, L"RansomShield: RegCreateKeyExW(%s) failed: error %ld\n", subKey, result);
        return false;
    }

    if (disposition == REG_CREATED_NEW_KEY) {
        wprintf(L"RansomShield: Created registry key: %s\n", subKey);
    }

    return true;
}

DWORD ConfigManager::ReadDWord(
    _In_ HKEY hKey,
    _In_ const wchar_t* valueName,
    _In_ DWORD defaultValue
) const
{
    DWORD data = 0;
    DWORD dataSize = sizeof(DWORD);
    DWORD type = 0;

    LONG result = RegQueryValueExW(
        hKey,
        valueName,
        NULL,           // lpReserved (must be NULL)
        &type,          // [out] Data type
        (LPBYTE)&data,  // [out] Data buffer
        &dataSize       // [in/out] Buffer size
    );

    if (result != ERROR_SUCCESS || type != REG_DWORD || dataSize != sizeof(DWORD)) {
        //
        // Value doesn't exist, is wrong type, or is wrong size.
        // Return the default value.
        //
        return defaultValue;
    }

    return data;
}

bool ConfigManager::WriteDWord(
    _In_ HKEY hKey,
    _In_ const wchar_t* valueName,
    _In_ DWORD value
) const
{
    LONG result = RegSetValueExW(
        hKey,
        valueName,
        0,              // Reserved (must be 0)
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&value),
        sizeof(DWORD)
    );

    return (result == ERROR_SUCCESS);
}
