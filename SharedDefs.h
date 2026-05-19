/*++
Module Name:
    SharedDefs.h

Abstract:
    Shared protocol definitions between the RansomShield minifilter driver
    (kernel-mode) and the RansomShield control application (user-mode).

    This header MUST be included by both the driver and the user-mode
    application to ensure protocol compatibility. Any changes to message
    types, structure layouts, or constants MUST be synchronized across
    both projects.

    PROTOCOL VERSION HISTORY:
    v1.0 - Initial: QueryBlockedPids, UnblockPid, NotifyBlockedPid
    v2.0 - Extended: UpdateConfig, UpdateAllowlist, Pause/Resume, ClearAllowlist

    MESSAGE FLOW DIAGRAM:

    User-Mode                                   Kernel-Mode
    ─────────                                   ───────────
    FilterConnectCommunicationPort()  ──────►   ConnectNotifyCallback()
                                                    (accept connection)

    FilterGetMessage()  ◄───────────────   FltSendMessage()
         (notification loop)                   (push alert on block)

    FilterSendMessage(RsQueryBlockedPids) ──►  MessageNotifyCallback()
         ◄──────────────────────────────       (reply with list)

    FilterSendMessage(RsRequestUnblockPid) ──► MessageNotifyCallback()
         ◄──────────────────────────────       (reply with status)

    FilterSendMessage(RsUpdateConfig) ──────►  MessageNotifyCallback()
         ◄──────────────────────────────       (apply new thresholds)

    FilterSendMessage(RsUpdateAllowlist) ───►  MessageNotifyCallback()
         ◄──────────────────────────────       (replace allowlist)

    FilterSendMessage(RsPauseMonitoring) ───►  MessageNotifyCallback()
         ◄──────────────────────────────       (stop blocking)

    FilterSendMessage(RsResumeMonitoring) ───► MessageNotifyCallback()
         ◄──────────────────────────────       (resume blocking)

    BUFFER LAYOUT IN FILTER MANAGER:

    When the kernel calls FltSendMessage(), the filter manager prepends
    a FILTER_MESSAGE_HEADER to the data. When the user-mode client calls
    FilterGetMessage(), it must provide a buffer large enough for:

        FILTER_MESSAGE_HEADER + RS_NOTIFICATION_xxx

    When the user-mode client calls FilterSendMessage(), it sends:

        RS_REQUEST_xxx (no FILTER_MESSAGE_HEADER needed; the manager adds it)

    When the kernel replies (in MessageNotifyCallback), it writes:

        RS_REPLY_xxx into the OutputBuffer

Author:
    RansomShield Development

Environment:
    Shared between kernel-mode and user-mode
--*/

#ifndef _SHARED_DEFS_H_
#define _SHARED_DEFS_H_

//
// We need different declarations depending on whether this header is included
// from kernel mode or user mode. In kernel mode, we use NT types directly.
// In user mode, we use Windows.h types and define compatibility macros.
//
#ifdef _KERNEL_MODE
    #include <fltkernel.h>
#else
    #include <windows.h>
    // NTSTATUS is not transitively defined by windows.h alone in all SDK configurations.
    // In kernel mode it comes from ntdef.h; in user mode we define the equivalent type here.
    // Guard matches winternl.h and ntdef.h so we don't double-define.
    #if !defined(_NTSTATUS_DEFINED) && !defined(_NTDEF_)
    #define _NTSTATUS_DEFINED
    typedef long NTSTATUS;
    #endif
#endif

//
// ============================================================================
// PROTOCOL VERSION
// ============================================================================
//

#define RS_PROTOCOL_VERSION        2

//
// ============================================================================
// PORT NAME
// ============================================================================
//
// The communication port name. Both kernel and user mode must use the
// same name. The leading backslash is required; the filter manager
// resolves it under the \Device\ namespace.
//
#define RS_PORT_NAME               L"\\RansomShieldPort"

//
// ============================================================================
// HEURISTIC CONFIGURATION DEFAULTS
// ============================================================================
//
// These defaults are used when no registry configuration exists.
// The user-mode service loads these from the registry on startup
// and pushes them to the driver via RsUpdateConfig.
//

#define RS_DEFAULT_FILE_COUNT_THRESHOLD    50
#define RS_DEFAULT_TIME_WINDOW_SECONDS     10
#define RS_DEFAULT_MONITORING_ENABLED      TRUE

//
// ============================================================================
// STRING & BUFFER LIMITS
// ============================================================================
//

#define RS_MAX_IMAGE_NAME_LEN              260    // WCHARs, including null
#define RS_MAX_ALLOWLIST_ENTRIES           128    // Max allowlist entries
#define RS_MAX_ALLOWLIST_NAME_LEN          260    // WCHARs per entry
#define RS_MAX_REPORT_BLOCKED              256    // Max PIDs in query reply
#define RS_MAX_ALLOWLIST_CHUNK             32     // Entries per chunk message

//
// ============================================================================
// MESSAGE TYPES
// ============================================================================
//
// Enumerates all message types in the protocol. Each message type maps to
// a specific request/reply/notification structure.
//
// Numbering convention:
//   1-99:     Kernel -> User notifications (unsolicited pushes)
//   100-199:  User -> Kernel queries (request/response)
//   200-299:  User -> Kernel commands (request/response)
//   300-399:  User -> Kernel configuration (request/response)
//
typedef enum _RS_MESSAGE_TYPE {

    // ─── NOTIFICATIONS (Kernel -> User) ────────────────────────────

    //
    // A process has been flagged as ransomware and blocked.
    // Payload: RS_NOTIFICATION_BLOCKED_PID
    //
    RsNotifyBlockedPid = 1,

    //
    // A configuration update has been acknowledged by the driver.
    // Payload: RS_NOTIFICATION_CONFIG_UPDATED
    //
    RsNotifyConfigUpdated = 2,

    //
    // An allowlist update has been acknowledged by the driver.
    // Payload: RS_NOTIFICATION_ALLOWLIST_UPDATED
    //
    RsNotifyAllowlistUpdated = 3,

    // ─── QUERIES (User -> Kernel, request/response) ────────────────

    //
    // Query the list of currently blocked PIDs.
    // Request:  RS_REQUEST_BLOCKED_PIDS
    // Response: RS_REPLY_BLOCKED_PIDS
    //
    RsQueryBlockedPids = 100,

    //
    // Query the driver's current configuration (thresholds, monitoring state).
    // Request:  RS_REQUEST_QUERY_CONFIG
    // Response: RS_REPLY_CONFIG
    //
    RsQueryConfig = 110,

    //
    // Query the driver's current allowlist.
    // Request:  RS_REQUEST_QUERY_ALLOWLIST
    // Response: RS_REPLY_ALLOWLIST
    //
    RsQueryAllowlist = 120,

    // ─── COMMANDS (User -> Kernel, request/response) ───────────────

    //
    // Unblock a specific PID that was previously blocked.
    // Request:  RS_REQUEST_UNBLOCK_PID
    // Response: RS_REPLY_UNBLOCK_PID
    //
    RsRequestUnblockPid = 200,

    //
    // Pause monitoring (stop blocking but continue tracking).
    // Request:  RS_REQUEST_PAUSE
    // Response: RS_REPLY_GENERIC
    //
    RsRequestPause = 210,

    //
    // Resume monitoring (re-enable blocking after pause).
    // Request:  RS_REQUEST_RESUME
    // Response: RS_REPLY_GENERIC
    //
    RsRequestResume = 211,

    // ─── CONFIGURATION (User -> Kernel, request/response) ──────────

    //
    // Update heuristic configuration (thresholds, time window).
    // Request:  RS_REQUEST_UPDATE_CONFIG
    // Response: RS_REPLY_GENERIC
    //
    RsUpdateConfig = 300,

    //
    // Clear the driver's entire allowlist (prelude to reloading).
    // Request:  RS_REQUEST_CLEAR_ALLOWLIST
    // Response: RS_REPLY_GENERIC
    //
    RsClearAllowlist = 310,

    //
    // Send a chunk of allowlist entries to the driver.
    // Request:  RS_REQUEST_UPDATE_ALLOWLIST_CHUNK
    // Response: RS_REPLY_GENERIC
    //
    RsUpdateAllowlistChunk = 311,

    //
    // Send the full allowlist in one message (for small lists).
    // Request:  RS_REQUEST_UPDATE_ALLOWLIST_FULL
    // Response: RS_REPLY_GENERIC
    //
    RsUpdateAllowlistFull = 312,

} RS_MESSAGE_TYPE, *PRS_MESSAGE_TYPE;

//
// ============================================================================
// COMMON HEADER
// ============================================================================
//
// Every message (in both directions) starts with this header.
// The SequenceNumber is for debugging/auditing; the kernel driver
// increments its own counter, and the user-mode app can do the same.
//
typedef struct _RS_MESSAGE_HEADER {
    RS_MESSAGE_TYPE     MessageType;        // Type of this message
    ULONG               MessageSize;        // Total size including this header
    ULONG               SequenceNumber;     // Monotonically increasing counter
    ULONG               ProtocolVersion;    // Protocol version for compat checks
} RS_MESSAGE_HEADER, *PRS_MESSAGE_HEADER;

//
// ============================================================================
// NOTIFICATION STRUCTURES (Kernel -> User)
// ============================================================================
//

//
// Notification: A process has been blocked.
//
typedef struct _RS_NOTIFICATION_BLOCKED_PID {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsNotifyBlockedPid
    ULONG               ProcessId;          // The blocked PID
    WCHAR               ImageName[RS_MAX_IMAGE_NAME_LEN];
    LONGLONG            BlockedTimestamp;   // 100ns ticks since boot
    ULONG               OperationCount;     // Ops that triggered the block
} RS_NOTIFICATION_BLOCKED_PID, *PRS_NOTIFICATION_BLOCKED_PID;

//
// Notification: Configuration was updated.
//
typedef struct _RS_NOTIFICATION_CONFIG_UPDATED {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsNotifyConfigUpdated
    ULONG               FileCountThreshold; // New threshold value
    ULONG               TimeWindowSeconds;  // New time window value
    BOOLEAN             MonitoringEnabled;  // New monitoring state
} RS_NOTIFICATION_CONFIG_UPDATED, *PRS_NOTIFICATION_CONFIG_UPDATED;

//
// Notification: Allowlist was updated.
//
typedef struct _RS_NOTIFICATION_ALLOWLIST_UPDATED {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsNotifyAllowlistUpdated
    ULONG               EntryCount;         // Number of entries now in the list
} RS_NOTIFICATION_ALLOWLIST_UPDATED, *PRS_NOTIFICATION_ALLOWLIST_UPDATED;

//
// ============================================================================
// QUERY REQUEST/REPLY STRUCTURES
// ============================================================================
//

//
// Request: Query blocked PIDs.
//
typedef struct _RS_REQUEST_BLOCKED_PIDS {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsQueryBlockedPids
} RS_REQUEST_BLOCKED_PIDS, *PRS_REQUEST_BLOCKED_PIDS;

//
// Reply: List of blocked PIDs.
//
typedef struct _RS_BLOCKED_PID_ENTRY {
    ULONG               ProcessId;
    WCHAR               ImageName[RS_MAX_IMAGE_NAME_LEN];
    LONGLONG            BlockedTimestamp;
    ULONG               OperationCount;
} RS_BLOCKED_PID_ENTRY, *PRS_BLOCKED_PID_ENTRY;

typedef struct _RS_REPLY_BLOCKED_PIDS {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsQueryBlockedPids (echo)
    ULONG               Count;              // Number of entries
    RS_BLOCKED_PID_ENTRY Entries[RS_MAX_REPORT_BLOCKED];
} RS_REPLY_BLOCKED_PIDS, *PRS_REPLY_BLOCKED_PIDS;

//
// Request: Query current configuration.
//
typedef struct _RS_REQUEST_QUERY_CONFIG {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsQueryConfig
} RS_REQUEST_QUERY_CONFIG, *PRS_REQUEST_QUERY_CONFIG;

//
// Reply: Current driver configuration.
//
typedef struct _RS_REPLY_CONFIG {
    RS_MESSAGE_HEADER   Header;
    ULONG               FileCountThreshold; // Current threshold
    ULONG               TimeWindowSeconds;  // Current time window
    BOOLEAN             MonitoringEnabled;  // TRUE = active, FALSE = paused
    ULONG               TrackedPidCount;    // Current number of tracked PIDs
    ULONG               BlockedPidCount;    // Current number of blocked PIDs
} RS_REPLY_CONFIG, *PRS_REPLY_CONFIG;

//
// Request: Query current allowlist.
//
typedef struct _RS_REQUEST_QUERY_ALLOWLIST {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsQueryAllowlist
} RS_REQUEST_QUERY_ALLOWLIST, *PRS_REQUEST_QUERY_ALLOWLIST;

//
// Reply: Current allowlist entries.
//
typedef struct _RS_REPLY_ALLOWLIST {
    RS_MESSAGE_HEADER   Header;
    ULONG               Count;              // Number of entries in Entries[]
    WCHAR               Entries[RS_MAX_ALLOWLIST_ENTRIES][RS_MAX_ALLOWLIST_NAME_LEN];
} RS_REPLY_ALLOWLIST, *PRS_REPLY_ALLOWLIST;

//
// ============================================================================
// COMMAND REQUEST/REPLY STRUCTURES
// ============================================================================
//

//
// Request: Unblock a PID.
//
typedef struct _RS_REQUEST_UNBLOCK_PID {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsRequestUnblockPid
    ULONG               ProcessId;
} RS_REQUEST_UNBLOCK_PID, *PRS_REQUEST_UNBLOCK_PID;

//
// Reply: Unblock result.
//
typedef struct _RS_REPLY_UNBLOCK_PID {
    RS_MESSAGE_HEADER   Header;
    NTSTATUS            Status;             // 0 = success, or error code
    ULONG               ProcessId;          // PID that was (or wasn't) unblocked
} RS_REPLY_UNBLOCK_PID, *PRS_REPLY_UNBLOCK_PID;

//
// Request: Pause monitoring.
//
typedef struct _RS_REQUEST_PAUSE {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsRequestPause
} RS_REQUEST_PAUSE, *PRS_REQUEST_PAUSE;

//
// Request: Resume monitoring.
//
typedef struct _RS_REQUEST_RESUME {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsRequestResume
} RS_REQUEST_RESUME, *PRS_REQUEST_RESUME;

//
// ============================================================================
// CONFIGURATION REQUEST/REPLY STRUCTURES
// ============================================================================
//

//
// Request: Update heuristic configuration.
//
typedef struct _RS_REQUEST_UPDATE_CONFIG {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsUpdateConfig
    ULONG               FileCountThreshold; // New threshold (0 = no change)
    ULONG               TimeWindowSeconds;  // New time window (0 = no change)
    BOOLEAN             MonitoringEnabled;  // New monitoring state (ignored if neither threshold nor window changed)
} RS_REQUEST_UPDATE_CONFIG, *PRS_REQUEST_UPDATE_CONFIG;

//
// Request: Clear the driver's allowlist.
// Used before pushing a new allowlist to ensure no stale entries remain.
//
typedef struct _RS_REQUEST_CLEAR_ALLOWLIST {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsClearAllowlist
} RS_REQUEST_CLEAR_ALLOWLIST, *PRS_REQUEST_CLEAR_ALLOWLIST;

//
// Request: Send a chunk of allowlist entries.
// For large allowlists, send multiple chunks after clearing.
// ChunkIndex is 0-based; ChunkCount is the total number of chunks.
// EntryCount is the number of valid entries in this chunk's Entries[].
//
typedef struct _RS_REQUEST_UPDATE_ALLOWLIST_CHUNK {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsUpdateAllowlistChunk
    ULONG               ChunkIndex;         // 0-based chunk number
    ULONG               ChunkCount;         // Total chunks in this batch
    ULONG               EntryCount;         // Valid entries in Entries[]
    WCHAR               Entries[RS_MAX_ALLOWLIST_CHUNK][RS_MAX_ALLOWLIST_NAME_LEN];
} RS_REQUEST_UPDATE_ALLOWLIST_CHUNK, *PRS_REQUEST_UPDATE_ALLOWLIST_CHUNK;

//
// Request: Send the full allowlist in one message.
// Only suitable for small allowlists (<= RS_MAX_ALLOWLIST_ENTRIES).
//
typedef struct _RS_REQUEST_UPDATE_ALLOWLIST_FULL {
    RS_MESSAGE_HEADER   Header;             // MessageType = RsUpdateAllowlistFull
    ULONG               EntryCount;         // Valid entries in Entries[]
    WCHAR               Entries[RS_MAX_ALLOWLIST_ENTRIES][RS_MAX_ALLOWLIST_NAME_LEN];
} RS_REQUEST_UPDATE_ALLOWLIST_FULL, *PRS_REQUEST_UPDATE_ALLOWLIST_FULL;

//
// ============================================================================
// GENERIC REPLY (used for commands that only need success/failure)
// ============================================================================
//

typedef struct _RS_REPLY_GENERIC {
    RS_MESSAGE_HEADER   Header;
    NTSTATUS            Status;             // STATUS_SUCCESS (0) or error
    ULONG               ExtraInfo;          // Optional extra data
} RS_REPLY_GENERIC, *PRS_REPLY_GENERIC;

//
// ============================================================================
// REGISTRY PATH CONSTANTS
// ============================================================================
//
// The user-mode service persists configuration under this registry key.
// This is separate from the driver's service key to avoid permission
// issues — the service writes to its own subkey.
//

#define RS_REGISTRY_BASE_PATH   L"SYSTEM\\CurrentControlSet\\Services\\RansomShield"
#define RS_REGISTRY_CONFIG_KEY  L"Config"
#define RS_REGISTRY_ALLOWLIST_KEY L"Allowlist"

//
// Registry value names under Config subkey
//
#define RS_REGVAL_THRESHOLD     L"FileCountThreshold"
#define RS_REGVAL_TIMEWINDOW    L"TimeWindowSeconds"
#define RS_REGVAL_MONITORING    L"MonitoringEnabled"
#define RS_REGVAL_VERSION       L"ProtocolVersion"

//
// Registry value names under Allowlist subkey
// Each entry is stored as: "Entry00" = L"svchost.exe", "Entry01" = L"MsMpEng.exe", etc.
//
#define RS_REGVAL_ENTRY_PREFIX  L"Entry"

//
// ============================================================================
// EVENT LOG CONSTANTS
// ============================================================================
//

#define RS_EVENT_LOG_SOURCE     L"RansomShield"
#define RS_EVENT_CATEGORY       1

//
// Event IDs for the Windows Event Log.
// These must match a message compiler (.mc) file in production.
//
#define RS_EVENT_INFO_SERVICE_START     1001
#define RS_EVENT_INFO_CONFIG_LOADED     1002
#define RS_EVENT_INFO_PID_BLOCKED       1003
#define RS_EVENT_INFO_PID_UNBLOCKED     1004
#define RS_EVENT_INFO_ALLOWLIST_UPDATED 1005
#define RS_EVENT_WARN_DRIVER_NOT_FOUND  2001
#define RS_EVENT_WARN_DRIVER_DISCONNECT 2002
#define RS_EVENT_ERROR_COMM_FAILURE     3001
#define RS_EVENT_ERROR_REGISTRY_FAILURE 3002

#endif /* _SHARED_DEFS_H_ */
