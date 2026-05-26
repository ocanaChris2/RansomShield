#pragma once

#include "../../sdk/IProtectionModule.h"
#include "CommManager.h"
#include "ConfigManager.h"
#include "EventLogger.h"
#include "SharedDefs.h"

/*
 * RansomShieldModule — concrete IProtectionModule for the ransomware-blocking
 * minifilter driver.  Owns the three manager objects and coordinates them:
 *   - CommManager  : kernel communication port
 *   - ConfigManager: registry persistence + driver sync
 *   - EventLogger  : Windows Event Log + file log
 *
 * Usage (CLI or tray):
 *
 *   RansomShieldModule mod;
 *   mod.Initialize();
 *   if (SUCCEEDED(mod.Connect())) {
 *       mod.PushToDriver();
 *       mod.StartListener(myCallback);
 *   }
 */
class RansomShieldModule : public IProtectionModule {
public:
    RansomShieldModule();

    // IProtectionModule
    const wchar_t* GetName()    const override { return L"RansomShield"; }
    const wchar_t* GetVersion() const override { return L"1.0.0"; }
    bool      Initialize()  override;
    HRESULT   Connect()     override;
    void      Disconnect()  override;
    void      Shutdown()    override;

    // ── Accessors ─────────────────────────────────────────────────────────────
    CommManager&   Comm()   { return m_comm;   }
    ConfigManager& Config() { return m_config; }
    EventLogger&   Logger() { return m_logger; }

    // ── Convenience wrappers ──────────────────────────────────────────────────

    // Push current registry config + allowlist to the driver.
    bool PushToDriver();

    // Start/stop the background driver notification listener.
    HRESULT StartListener(NotificationCallback cb);
    void    StopListener();

private:
    CommManager   m_comm;
    ConfigManager m_config;
    EventLogger   m_logger;
};
