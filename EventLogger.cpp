/*++
Module Name:
    EventLogger.cpp

Abstract:
    Implementation of the Event Logger. See EventLogger.h for design rationale.

    WINDOWS EVENT LOG API OVERVIEW:

    1. RegisterEventSourceW()
       - Opens a handle to the Application event log for writing.
       - The source name must match a registered event source in the
         registry. If not registered, the events will still be written
         but won't have proper message formatting.
       - Returns a handle that must be closed with DeregisterEventSource().

    2. ReportEventW()
       - Writes an event to the event log.
       - Parameters include: event type (ERROR, WARNING, INFO),
         event ID, category, and optional insert strings.
       - The insert strings are combined with the message template
         from the event message file to produce the final log text.
       - If no message file is registered, the raw insert strings
         are displayed.

    3. DeregisterEventSource()
       - Closes the event source handle.

    LOG FILE FORMAT:
    The local log file uses a simple text format for easy parsing:
        [TIMESTAMP] [LEVEL] Message text
    Example:
        [2026-05-17 14:30:22] [ALERT] Ransomware detected: PID 4816 (encrypt.exe) - 127 ops

Author:
    RansomShield Development
--*/

#include "EventLogger.h"
#include "SharedDefs.h"
#include <cstdarg>
#include <cstdio>
#include <ctime>

// ============================================================================
// SINGLETON
// ============================================================================

EventLogger& EventLogger::Instance()
{
    static EventLogger instance;
    return instance;
}

EventLogger::EventLogger()
    : m_hEventLog(NULL)
    , m_hLogFile(INVALID_HANDLE_VALUE)
    , m_initialized(false)
{
}

EventLogger::~EventLogger()
{
    if (m_hEventLog) {
        DeregisterEventSource(m_hEventLog);
        m_hEventLog = NULL;
    }

    if (m_hLogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hLogFile);
        m_hLogFile = INVALID_HANDLE_VALUE;
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool EventLogger::Initialize()
{
    if (m_initialized) {
        return true;
    }

    //
    // Register the event source with the Windows Event Log.
    //
    // RegisterEventSourceW looks up the source name in:
    //   HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\RansomShield
    //
    // If the registry key doesn't exist (which it won't on first run
    // without a proper installer), the events will still be written to
    // the Application log, but the Event Viewer will show:
    //   "The description for Event ID xxx from source RansomShield cannot be found."
    //
    // A production installer should create this registry key and point
    // it to the event message file (.dll compiled from .mc).
    //
    m_hEventLog = RegisterEventSourceW(NULL, RS_EVENT_LOG_SOURCE);

    if (m_hEventLog == NULL) {
        fwprintf(stderr, L"RansomShield: RegisterEventSourceW failed: %lu\n", GetLastError());
        //
        // Non-fatal: We can still log to the file. The event log is
        // a nice-to-have, not a requirement.
        //
    }

    //
    // Open (or create) the local log file.
    // The log file is stored in the same directory as the executable.
    // In production, this would be %ProgramData%\RansomShield\ or similar.
    //
    WCHAR logPath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, logPath, MAX_PATH);

    //
    // Replace the .exe extension with .log
    //
    WCHAR* lastDot = wcsrchr(logPath, L'.');
    if (lastDot != NULL) {
        wcscpy_s(lastDot, MAX_PATH - (lastDot - logPath), L".log");
    } else {
        wcscat_s(logPath, MAX_PATH, L".log");
    }

    m_hLogFile = CreateFileW(
        logPath,
        FILE_APPEND_DATA,       // Append to existing file
        FILE_SHARE_READ,        // Allow other processes to read
        NULL,                   // Default security
        OPEN_ALWAYS,            // Open existing or create new
        FILE_ATTRIBUTE_NORMAL,
        NULL                    // No template
    );

    if (m_hLogFile == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"RansomShield: Failed to open log file '%s': %lu\n",
                 logPath, GetLastError());
        //
        // Non-fatal: We can still log to the event log.
        //
    }

    m_initialized = true;

    LogInfo(L"RansomShield service started. Log file: %s", logPath);

    return true;
}

// ============================================================================
// EVENT-SPECIFIC LOGGING
// ============================================================================

void EventLogger::LogRansomwareDetected(
    _In_ ULONG pid,
    _In_ const wchar_t* imageName,
    _In_ ULONG operationCount
)
{
    //
    // Format a human-readable message for the event log.
    //
    WCHAR message[512];
    swprintf_s(message, _countof(message),
               L"Ransomware behavior detected: PID %lu (%s) modified %lu files within the detection window. "
               L"All write operations from this process have been blocked.",
               pid, imageName ? imageName : L"unknown", operationCount);

    //
    // Write to the Windows Event Log as an ERROR type (security alert).
    //
    const wchar_t* strings[1] = { message };
    WriteEventLog(EVENTLOG_ERROR_TYPE, RS_EVENT_INFO_PID_BLOCKED, 1, strings);

    //
    // Also write to the local log file.
    //
    WriteLogFile(L"ALERT", message);
}

void EventLogger::LogPidUnblocked(
    _In_ ULONG pid,
    _In_ const wchar_t* imageName
)
{
    WCHAR message[512];
    swprintf_s(message, _countof(message),
               L"PID %lu (%s) has been unblocked by administrator action. "
               L"Write operations will be allowed.",
               pid, imageName ? imageName : L"unknown");

    const wchar_t* strings[1] = { message };
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, RS_EVENT_INFO_PID_UNBLOCKED, 1, strings);

    WriteLogFile(L"INFO", message);
}

void EventLogger::LogConfigChanged(
    _In_ ULONG threshold,
    _In_ ULONG timeWindow,
    _In_ bool monitoringEnabled
)
{
    WCHAR message[512];
    swprintf_s(message, _countof(message),
               L"Configuration updated: Threshold=%lu files, TimeWindow=%lu seconds, Monitoring=%s",
               threshold, timeWindow, monitoringEnabled ? L"Enabled" : L"Disabled");

    const wchar_t* strings[1] = { message };
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, RS_EVENT_INFO_CONFIG_LOADED, 1, strings);

    WriteLogFile(L"CONFIG", message);
}

void EventLogger::LogAllowlistChanged(
    _In_ const wchar_t* action,
    _In_ const wchar_t* imageName
)
{
    WCHAR message[512];
    swprintf_s(message, _countof(message),
               L"Allowlist %s: %s", action, imageName);

    const wchar_t* strings[1] = { message };
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, RS_EVENT_INFO_ALLOWLIST_UPDATED, 1, strings);

    WriteLogFile(L"CONFIG", message);
}

void EventLogger::LogInfo(_In_ const wchar_t* format, ...)
{
    WCHAR message[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(message, _countof(message), format, args);
    va_end(args);

    const wchar_t* strings[1] = { message };
    WriteEventLog(EVENTLOG_INFORMATION_TYPE, RS_EVENT_INFO_SERVICE_START, 1, strings);
    WriteLogFile(L"INFO", message);
}

void EventLogger::LogWarning(_In_ const wchar_t* format, ...)
{
    WCHAR message[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(message, _countof(message), format, args);
    va_end(args);

    const wchar_t* strings[1] = { message };
    WriteEventLog(EVENTLOG_WARNING_TYPE, RS_EVENT_WARN_DRIVER_NOT_FOUND, 1, strings);
    WriteLogFile(L"WARN", message);
}

void EventLogger::LogError(_In_ const wchar_t* format, ...)
{
    WCHAR message[1024];
    va_list args;
    va_start(args, format);
    vswprintf_s(message, _countof(message), format, args);
    va_end(args);

    const wchar_t* strings[1] = { message };
    WriteEventLog(EVENTLOG_ERROR_TYPE, RS_EVENT_ERROR_COMM_FAILURE, 1, strings);
    WriteLogFile(L"ERROR", message);
}

// ============================================================================
// NOTIFICATION DISPATCH
// ============================================================================

void EventLogger::HandleNotification(
    _In_ const BYTE* data,
    _In_ DWORD dataSize
)
{
    if (data == NULL || dataSize < sizeof(RS_MESSAGE_HEADER)) {
        return;
    }

    //
    // Cast the data to our message header to determine the type.
    // All notification messages start with RS_MESSAGE_HEADER.
    //
    const RS_MESSAGE_HEADER* header = reinterpret_cast<const RS_MESSAGE_HEADER*>(data);

    switch (header->MessageType) {

    case RsNotifyBlockedPid:
    {
        //
        // A process was flagged as ransomware and blocked.
        // Validate the buffer size before casting.
        //
        if (dataSize >= sizeof(RS_NOTIFICATION_BLOCKED_PID)) {
            const RS_NOTIFICATION_BLOCKED_PID* notif =
                reinterpret_cast<const RS_NOTIFICATION_BLOCKED_PID*>(data);

            LogRansomwareDetected(
                notif->ProcessId,
                notif->ImageName,
                notif->OperationCount
            );

            //
            // Additional actions could be taken here:
            //   - Kill the offending process (TerminateProcess).
            //   - Isolate the machine from the network.
            //   - Take a volume snapshot (VSS) for recovery.
            //   - Send a network alert to a SIEM/SOAR system.
            //
            // For safety, we only log the event. The administrator
            // can take manual action or configure automated responses.
            //
            wprintf(L"\n╔══════════════════════════════════════════════════╗\n");
            wprintf(L"║  RANSOMWARE DETECTED                            ║\n");
            wprintf(L"║  PID: %-8lu  Image: %-28s ║\n", notif->ProcessId, notif->ImageName);
            wprintf(L"║  Operations: %-6lu in detection window          ║\n", notif->OperationCount);
            wprintf(L"║  Status: BLOCKED — All writes denied            ║\n");
            wprintf(L"╚══════════════════════════════════════════════════╝\n\n");
        }
        break;
    }

    case RsNotifyConfigUpdated:
    {
        if (dataSize >= sizeof(RS_NOTIFICATION_CONFIG_UPDATED)) {
            const RS_NOTIFICATION_CONFIG_UPDATED* notif =
                reinterpret_cast<const RS_NOTIFICATION_CONFIG_UPDATED*>(data);

            LogConfigChanged(
                notif->FileCountThreshold,
                notif->TimeWindowSeconds,
                notif->MonitoringEnabled ? true : false
            );
        }
        break;
    }

    case RsNotifyAllowlistUpdated:
    {
        if (dataSize >= sizeof(RS_NOTIFICATION_ALLOWLIST_UPDATED)) {
            const RS_NOTIFICATION_ALLOWLIST_UPDATED* notif =
                reinterpret_cast<const RS_NOTIFICATION_ALLOWLIST_UPDATED*>(data);

            LogInfo(L"Driver allowlist updated: %lu entries", notif->EntryCount);
        }
        break;
    }

    default:
        //
        // Unknown notification type. Log it for debugging.
        //
        LogWarning(L"Unknown notification type: %d (size=%lu)",
                   header->MessageType, dataSize);
        break;
    }
}

// ============================================================================
// INTERNAL LOGGING
// ============================================================================

void EventLogger::WriteEventLog(
    _In_ WORD eventType,
    _In_ DWORD eventId,
    _In_ WORD numStrings,
    _In_reads_(numStrings) const wchar_t** strings
)
{
    if (m_hEventLog == NULL) {
        return;
    }

    //
    // ReportEventW writes an entry to the Windows Event Log.
    //
    // Parameters:
    //   hLog           - Handle from RegisterEventSourceW.
    //   wType          - EVENTLOG_ERROR_TYPE, WARNING_TYPE, INFORMATION_TYPE.
    //   wCategory      - Event category (we use 1 = default).
    //   dwEventID      - Event ID (matches .mc file definitions).
    //   lpUserSid      - User security identifier (NULL = no user).
    //   wNumStrings    - Number of insert strings.
    //   dwDataSize     - Size of raw binary data (0 if none).
    //   lpStrings      - Array of insert string pointers.
    //   lpRawData      - Raw binary data (NULL if none).
    //
    ReportEventW(
        m_hEventLog,
        eventType,
        RS_EVENT_CATEGORY,
        eventId,
        NULL,               // lpUserSid
        numStrings,
        0,                  // dwDataSize
        strings,
        NULL                // lpRawData
    );
}

void EventLogger::WriteLogFile(
    _In_ const wchar_t* level,
    _In_ const wchar_t* message
)
{
    if (m_hLogFile == INVALID_HANDLE_VALUE) {
        return;
    }

    //
    // Format: [YYYY-MM-DD HH:MM:SS] [LEVEL] Message\r\n
    //
    SYSTEMTIME st;
    GetLocalTime(&st);

    WCHAR line[2048];
    int len = swprintf_s(line, _countof(line),
                         L"[%04d-%02d-%02d %02d:%02d:%02d] [%-6s] %s\r\n",
                         st.wYear, st.wMonth, st.wDay,
                         st.wHour, st.wMinute, st.wSecond,
                         level, message);

    if (len <= 0) {
        return;
    }

    //
    // Write to the log file.
    // We don't need a critical section here because:
    //   1. The listener thread is the primary caller.
    //   2. WriteFile with FILE_APPEND_DATA is atomic for writes
    //      under 4KB on NTFS (our messages are well under that).
    //   3. If concurrent writes did interleave, the worst case
    //      is garbled log lines — not a crash or data corruption.
    //
    DWORD bytesWritten = 0;
    WriteFile(
        m_hLogFile,
        line,
        static_cast<DWORD>(len * sizeof(WCHAR)),
        &bytesWritten,
        NULL    // lpOverlapped (synchronous)
    );
}
