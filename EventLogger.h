/*++
Module Name:
    EventLogger.h

Abstract:
    Event Logger for the RansomShield user-mode control application.
    Handles:
      - Logging ransomware detection events to the Windows Event Log.
      - Logging to a local file as a fallback/secondary log.
      - Dispatching driver notifications to appropriate handlers.

    WHY USE THE WINDOWS EVENT LOG?
      1. The Windows Event Log is the standard logging mechanism for
         Windows services. It integrates with Event Viewer, SIEM systems,
         and monitoring tools.
      2. Event Log entries are persistent across reboots and can be
         centrally managed via Group Policy.
      3. Security events (like ransomware detections) belong in the
         Security or Application log where administrators expect them.
      4. The Event Log API handles log rotation, size limits, and
         overflow policies automatically.

    EVENT LOG REGISTRATION:
    In production, the application must register an event message file
    (compiled from a .mc file) using the Event Message Compiler (mc.exe).
    This file defines the event IDs, categories, and message strings.
    For this implementation, we use ReportEventW with raw insert strings
    and register a simple source. Production deployments should create
    a proper .mc file and register it in the registry under:
      HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\RansomShield

Author:
    RansomShield Development
--*/

#pragma once

#include <Windows.h>
#include <string>

class EventLogger {
public:
    static EventLogger& Instance();
    ~EventLogger();

    //
    // Initialize the event logger. Registers the event source and
    // opens the log file. Must be called once at startup.
    //
    bool Initialize();

    //
    // Log a ransomware detection event.
    // This is the primary alert that triggers when a process is blocked.
    //
    void LogRansomwareDetected(
        _In_ ULONG pid,
        _In_ const wchar_t* imageName,
        _In_ ULONG operationCount
    );

    //
    // Log an unblock event.
    //
    void LogPidUnblocked(
        _In_ ULONG pid,
        _In_ const wchar_t* imageName
    );

    //
    // Log a configuration change.
    //
    void LogConfigChanged(
        _In_ ULONG threshold,
        _In_ ULONG timeWindow,
        _In_ bool monitoringEnabled
    );

    //
    // Log an allowlist change.
    //
    void LogAllowlistChanged(
        _In_ const wchar_t* action,
        _In_ const wchar_t* imageName
    );

    //
    // Log a general informational message.
    //
    void LogInfo(
        _In_ const wchar_t* format,
        ...
    );

    //
    // Log a warning message.
    //
    void LogWarning(
        _In_ const wchar_t* format,
        ...
    );

    //
    // Log an error message.
    //
    void LogError(
        _In_ const wchar_t* format,
        ...
    );

    //
    // Handle a raw notification from the driver.
    // Dispatches to the appropriate logging method based on message type.
    //
    void HandleNotification(
        _In_ const BYTE* data,
        _In_ DWORD dataSize
    );

private:
    EventLogger();
    EventLogger(const EventLogger&) = delete;
    EventLogger& operator=(const EventLogger&) = delete;

    //
    // Internal logging implementation.
    //
    void WriteEventLog(
        _In_ WORD eventType,
        _In_ DWORD eventId,
        _In_ WORD numStrings,
        _In_reads_(numStrings) const wchar_t** strings
    );

    void WriteLogFile(
        _In_ const wchar_t* level,
        _In_ const wchar_t* message
    );

    //
    // Event source handle for the Windows Event Log.
    // NULL if not registered.
    //
    HANDLE m_hEventLog;

    //
    // File handle for the local log file.
    // INVALID_HANDLE_VALUE if not open.
    //
    HANDLE m_hLogFile;

    //
    // Whether Initialize() has been called.
    //
    bool m_initialized;
};
