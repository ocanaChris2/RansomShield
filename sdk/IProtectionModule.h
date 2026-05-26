#pragma once

#include <Windows.h>

/*
 * IProtectionModule — abstract interface for a RansomShield protection engine.
 *
 * Each concrete module wraps a kernel driver + its user-mode support stack
 * (comm port, registry config, event log). Future modules (e.g. network
 * filtering, behaviour analytics) implement this same interface so the host
 * process or an AV orchestrator can manage them uniformly.
 */
struct IProtectionModule {
    virtual ~IProtectionModule() = default;

    // Human-readable module name (e.g. L"RansomShield").
    virtual const wchar_t* GetName()    const = 0;

    // Semver-style version string (e.g. L"1.0.0").
    virtual const wchar_t* GetVersion() const = 0;

    // One-time initialisation (registry, event log source, etc.).
    // Returns false on unrecoverable error.
    virtual bool      Initialize()  = 0;

    // Connect to the kernel driver.  May be retried after failure.
    virtual HRESULT   Connect()     = 0;

    // Disconnect from the kernel driver cleanly.
    virtual void      Disconnect()  = 0;

    // Tear down all resources acquired during Initialize().
    virtual void      Shutdown()    = 0;
};
