#include "RansomShieldModule.h"
#include <cstdio>

RansomShieldModule::RansomShieldModule()
    : m_comm(RS_PORT_NAME)
    , m_config(RS_REGISTRY_BASE_PATH)
    , m_logger(RS_EVENT_LOG_SOURCE)
{
}

bool RansomShieldModule::Initialize()
{
    m_logger.Initialize();
    return m_config.Initialize();
}

HRESULT RansomShieldModule::Connect()
{
    return m_comm.Connect();
}

void RansomShieldModule::Disconnect()
{
    m_comm.StopListener();
    m_comm.Disconnect();
}

void RansomShieldModule::Shutdown()
{
    Disconnect();
}

bool RansomShieldModule::PushToDriver()
{
    if (!m_comm.IsConnected()) {
        fwprintf(stderr, L"RansomShield: Cannot push to driver — not connected.\n");
        return false;
    }

    ULONG threshold  = m_config.GetFileCountThreshold();
    ULONG timeWindow = m_config.GetTimeWindowSeconds();
    bool  monitoring = m_config.IsMonitoringEnabled();
    auto  allowlist  = m_config.GetExceptions();

    HRESULT hr = m_comm.UpdateConfig(threshold, timeWindow, monitoring ? TRUE : FALSE);
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Failed to push config: 0x%08X\n", hr);
        return false;
    }

    hr = m_comm.PushAllowlist(allowlist);
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: Failed to push allowlist: 0x%08X\n", hr);
        return false;
    }

    return true;
}

HRESULT RansomShieldModule::StartListener(NotificationCallback cb)
{
    return m_comm.StartListener(cb);
}

void RansomShieldModule::StopListener()
{
    m_comm.StopListener();
}
