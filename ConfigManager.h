/*++
Module Name:
    ConfigManager.h

Abstract:
    Configuration and Allowlist Manager for the RansomShield user-mode
    control application. Handles:
      - Reading/writing heuristic thresholds to the Windows Registry.
      - Maintaining a thread-safe local cache of the allowlist.
      - Persisting allowlist entries to the Registry.
      - Loading all settings on startup and pushing them to the driver.

    REGISTRY LAYOUT:

    HKLM\SYSTEM\CurrentControlSet\Services\RansomShield\
        Config\
            FileCountThreshold  = REG_DWORD  (default: 50)
            TimeWindowSeconds   = REG_DWORD  (default: 10)
            MonitoringEnabled   = REG_DWORD  (default: 1)
            ProtocolVersion     = REG_DWORD  (default: 2)
        Allowlist\
            Entry00             = REG_SZ "svchost.exe"
            Entry01             = REG_SZ "SearchIndexer.exe"
            Entry02             = REG_SZ "MsMpEng.exe"
            ...

    WHY USE THE REGISTRY INSTEAD OF A CONFIG FILE?
      1. The Windows Registry is available early during boot, before the
         file system is fully initialized. A Windows Service that starts
         at boot time (SERVICE_AUTO_START) may not have access to config
         files on disk yet.
      2. Registry operations are atomic (single key read/write) and
         don't require file locking.
      3. Registry access is controlled by ACLs, so only Administrators
         and SYSTEM can modify the configuration.
      4. The registry is the standard configuration store for Windows
         services per Microsoft design guidelines.

    THREAD SAFETY:
    - The allowlist vector (m_allowlist) is protected by m_mutex.
    - The config values (m_threshold, m_timeWindow, m_monitoring) are
      simple DWORDs that are read/written atomically on x86/x64, but
      we protect them with the same mutex for consistency.
    - All public methods are thread-safe.

Author:
    RansomShield Development
--*/

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <mutex>

class ConfigManager {
public:
    //
    // Get the singleton instance.
    //
    static ConfigManager& Instance();

    ~ConfigManager();

    //
    // Initialize the ConfigManager. Creates registry keys if they don't
    // exist, loads settings from the registry, and applies defaults for
    // any missing values.
    //
    bool Initialize();

    // ─── Configuration Getters/Setters ──────────────────────────────

    ULONG GetFileCountThreshold() const;
    void  SetFileCountThreshold(ULONG threshold);

    ULONG GetTimeWindowSeconds() const;
    void  SetTimeWindowSeconds(ULONG seconds);

    bool  IsMonitoringEnabled() const;
    void  SetMonitoringEnabled(bool enabled);

    // ─── Allowlist Management ───────────────────────────────────────

    //
    // Add an image name to the allowlist. Returns false if the entry
    // already exists or the list is full.
    //
    bool AddException(const std::wstring& imageName);

    //
    // Remove an image name from the allowlist. Returns false if not found.
    //
    bool RemoveException(const std::wstring& imageName);

    //
    // Get a copy of the current allowlist.
    // Returns a vector of image name strings.
    //
    std::vector<std::wstring> GetExceptions() const;

    //
    // Check if an image name is in the allowlist.
    // Case-insensitive comparison (Windows filenames are case-insensitive).
    //
    bool IsException(const std::wstring& imageName) const;

    //
    // Clear all allowlist entries.
    //
    void ClearExceptions();

    // ─── Persistence ────────────────────────────────────────────────

    //
    // Save the current configuration and allowlist to the registry.
    // Called after any configuration change.
    //
    bool SaveToRegistry();

    //
    // Load configuration and allowlist from the registry.
    // Called during Initialize(). Can also be called to reload.
    //
    bool LoadFromRegistry();

    // ─── Driver Sync ────────────────────────────────────────────────

    //
    // Push the current configuration and allowlist to the driver.
    // This should be called:
    //   1. On startup, after loading from the registry.
    //   2. After any configuration change.
    //   3. After any allowlist change.
    //
    // Requires CommManager to be connected.
    //
    bool PushToDriver();

private:
    ConfigManager();
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    //
    // Helper: Open or create a registry key.
    //
    bool OpenOrCreateKey(
        _In_ HKEY hRootKey,
        _In_ const wchar_t* subKey,
        _Out_ PHKEY phKey
    ) const;

    //
    // Helper: Read a DWORD from the registry. Returns defaultValue on error.
    //
    DWORD ReadDWord(
        _In_ HKEY hKey,
        _In_ const wchar_t* valueName,
        _In_ DWORD defaultValue
    ) const;

    //
    // Helper: Write a DWORD to the registry.
    //
    bool WriteDWord(
        _In_ HKEY hKey,
        _In_ const wchar_t* valueName,
        _In_ DWORD value
    ) const;

    //
    // Configuration values.
    //
    ULONG   m_fileCountThreshold;
    ULONG   m_timeWindowSeconds;
    bool    m_monitoringEnabled;

    //
    // Allowlist entries. Protected by m_mutex.
    //
    std::vector<std::wstring> m_allowlist;

    //
    // Mutex for thread-safe access to configuration and allowlist.
    //
    mutable std::mutex m_mutex;

    //
    // Whether Initialize() has been called successfully.
    //
    bool m_initialized;

    //
    // Registry key handles (cached for performance).
    //
    HKEY m_hConfigKey;
    HKEY m_hAllowlistKey;
};
