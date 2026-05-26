/*++
Module Name:
    CommManager.h

Abstract:
    Communication Manager for the RansomShield user-mode control application.
    Manages the connection to the kernel minifilter driver via the Filter
    Manager user-mode API (fltuser.h / fltLib.lib).

    ARCHITECTURE:
    ┌────────────────────────────────────────────────────────────────┐
    │                    CommManager (Singleton)                     │
    │                                                                │
    │  Connect() ─── FilterConnectCommunicationPort() ──► Handle    │
    │                                                                │
    │  SendRequest() ─── FilterSendMessage() ──────────► Driver     │
    │       │                                                        │
    │       └──◄────── Reply buffer ◄────────────────── Driver      │
    │                                                                │
    │  Listener Thread:                                              │
    │    Loop {                                                      │
    │      FilterGetMessage() ───► Blocking wait for notification   │
    │      Dispatch to callback ──► EventHandler                    │
    │    }                                                           │
    │                                                                │
    │  Disconnect() ─── CloseHandle() ────────────────── Cleanup    │
    └────────────────────────────────────────────────────────────────┘

    THREAD SAFETY:
    - The m_cs lock protects m_hPort and m_connected.
    - The listener thread reads m_hPort (under lock) for FilterGetMessage.
    - SendRequest acquires the lock to read m_hPort, but releases it
      before calling FilterSendMessage (which may block).
    - Disconnect sets m_hPort = INVALID_HANDLE_VALUE under the lock,
      which causes the listener thread's FilterGetMessage to fail
      (the handle is closed after the listener thread exits).

    RECONNECTION:
    - If FilterGetMessage or FilterSendMessage fails with an error
      indicating the driver went away, the listener thread signals
      a reconnection event.
    - A reconnection timer (optional) can attempt to reconnect
      periodically. For a Windows Service, the SCM handles restarts.

Author:
    RansomShield Development

Environment:
    User mode, requires Administrator privileges
--*/

#pragma once

#include <Windows.h>
#include <FltUser.h>        // Filter Manager user-mode API
#include <string>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include "SharedDefs.h"

//
// Callback type for notifications received from the driver.
// The caller receives a pointer to the notification buffer and its size.
// The buffer is valid only for the duration of the callback.
//
using NotificationCallback = std::function<void(const BYTE* data, DWORD dataSize)>;

class CommManager {
public:
    // portName — the FltMgr port name to connect to (e.g. RS_PORT_NAME).
    explicit CommManager(const wchar_t* portName);

    //
    // Destructor ensures clean disconnection and thread shutdown.
    //
    ~CommManager();

    // ─── Connection Management ──────────────────────────────────────

    //
    // Connect to the RansomShield minifilter driver's communication port.
    //
    // FilterConnectCommunicationPort() is a synchronous call that
    // establishes a connection. It requires the caller to have
    // SeLoadDriverPrivilege (i.e., be an Administrator or SYSTEM).
    //
    // Returns S_OK on success, or an HRESULT error code.
    //
    HRESULT Connect();

    //
    // Disconnect from the driver. Stops the listener thread and closes
    // the port handle. Safe to call even if not connected.
    //
    void Disconnect();

    //
    // Check if currently connected to the driver.
    //
    bool IsConnected() const;

    // ─── Request/Response ───────────────────────────────────────────

    //
    // Send a request to the driver and receive a reply.
    //
    // This is a wrapper around FilterSendMessage() that handles
    // connection state checking, buffer sizing, and error translation.
    //
    // Parameters:
    //   request       - Pointer to the request structure (must start with
    //                   RS_MESSAGE_HEADER).
    //   requestSize   - Size of the request structure in bytes.
    //   reply         - [out] Buffer to receive the reply. May be NULL
    //                   if no reply is expected.
    //   replySize     - Size of the reply buffer in bytes. May be 0.
    //   bytesReturned - [out] Number of bytes actually written to reply.
    //                   May be NULL.
    //
    // Returns S_OK on success, or an HRESULT error code.
    //
    HRESULT SendRequest(
        _In_reads_bytes_(requestSize) const void* request,
        _In_ DWORD requestSize,
        _Out_writes_bytes_to_opt_(replySize, *bytesReturned) void* reply,
        _In_ DWORD replySize,
        _Out_opt_ DWORD* bytesReturned
    );

    // ─── Notification Listener ──────────────────────────────────────

    //
    // Start the background listener thread that receives unsolicited
    // notifications from the driver via FilterGetMessage().
    //
    // The listener thread runs a loop:
    //   1. Call FilterGetMessage() (blocks until a message arrives).
    //   2. Dispatch the message to the registered callback.
    //   3. Repeat until StopListener() is called or the port is closed.
    //
    // Parameters:
    //   callback - Function to call for each notification received.
    //
    HRESULT StartListener(NotificationCallback callback);

    //
    // Stop the background listener thread. Blocks until the thread
    // has exited (joins the thread).
    //
    void StopListener();

    // ─── Convenience Methods ────────────────────────────────────────

    //
    // Query the list of blocked PIDs from the driver.
    //
    HRESULT QueryBlockedPids(
        _Out_ RS_REPLY_BLOCKED_PIDS& reply
    );

    //
    // Query the driver's current configuration.
    //
    HRESULT QueryConfig(
        _Out_ RS_REPLY_CONFIG& reply
    );

    //
    // Query the driver's current allowlist.
    //
    HRESULT QueryAllowlist(
        _Out_ RS_REPLY_ALLOWLIST& reply
    );

    //
    // Unblock a specific PID.
    //
    HRESULT UnblockPid(
        _In_ ULONG pid,
        _Out_ RS_REPLY_UNBLOCK_PID& reply
    );

    //
    // Update the driver's heuristic configuration.
    //
    HRESULT UpdateConfig(
        _In_ ULONG fileCountThreshold,
        _In_ ULONG timeWindowSeconds,
        _In_ BOOLEAN monitoringEnabled
    );

    //
    // Pause monitoring (driver continues tracking but stops blocking).
    //
    HRESULT PauseMonitoring();

    //
    // Resume monitoring (re-enable blocking after pause).
    //
    HRESULT ResumeMonitoring();

    //
    // Push the full allowlist to the driver. For large lists, this
    // first clears the driver's list, then sends chunks.
    //
    HRESULT PushAllowlist(
        _In_ const std::vector<std::wstring>& entries
    );

private:
    CommManager(const CommManager&) = delete;
    CommManager& operator=(const CommManager&) = delete;

    //
    // Internal listener thread function.
    //
    void ListenerThreadProc();

    //
    // Helper: Build an RS_MESSAGE_HEADER with the current sequence number.
    //
    RS_MESSAGE_HEADER MakeHeader(RS_MESSAGE_TYPE type, ULONG messageSize);

    //
    // Handle port handle. INVALID_HANDLE_VALUE when not connected.
    // Protected by m_mutex.
    //
    HANDLE m_hPort;

    //
    // Whether we're currently connected.
    // Protected by m_mutex.
    //
    bool m_connected;

    //
    // Mutex protecting m_hPort and m_connected.
    //
    // We use std::mutex instead of CRITICAL_SECTION for:
    //   1. RAII compatibility with std::lock_guard.
    //   2. No initialization function needed (unlike InitializeCriticalSection).
    //   3. Same performance as CRITICAL_SECTION on modern Windows (SRWLock-based).
    //
    std::mutex m_mutex;

    //
    // Listener thread and control flags.
    //
    std::thread             m_listenerThread;
    std::atomic<bool>       m_listenerRunning;
    NotificationCallback    m_callback;

    //
    // Sequence number for outgoing requests.
    // Not thread-safe by itself, but only accessed under m_mutex.
    //
    ULONG m_sequenceNumber;

    std::wstring m_portName;
};
