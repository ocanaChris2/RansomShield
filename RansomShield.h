/*++
Module Name:
    RansomShield.h

Abstract:
    Header file for the RansomShield minifilter driver. This driver monitors
    IRP_MJ_WRITE and IRP_MJ_SET_INFORMATION operations to detect and block
    mass file overwrite/encryption attempts characteristic of ransomware.

    Architecture Overview:
    ┌──────────────────────────────────────────────────────────────────┐
    │                     RansomShield Driver                         │
    │                                                                  │
    │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
    │  │ Pre/Post    │  │ PID Context  │  │ Communication Port    │  │
    │  │ Callbacks   │──│ Tracker      │──│ (User-mode Telemetry) │  │
    │  │ (Filtering) │  │ (Heuristics) │  │                       │  │
    │  └─────────────┘  └──────────────┘  └───────────────────────┘  │
    │         │                │                     │                 │
    │  IRP_MJ_WRITE     Spinlock-protected    FltCreateCommPort      │
    │  IRP_MJ_SET_INFO  Hash Table of PIDs   FilterSendMessage      │
    └──────────────────────────────────────────────────────────────────┘

Author:
    RansomShield Development

Environment:
    Kernel mode only (FILE_SYSTEM_MINIFILTER driver)

IRQL Considerations:
    - Pre-operation callbacks: Called at PASSIVE_LEVEL or APC_LEVEL
    - Post-operation callbacks: Called at PASSIVE_LEVEL (we specify in flags)
    - Communication port callbacks: Called at PASSIVE_LEVEL
    - All shared data structures use spinlocks (KeAcquireSpinLock) which
      raise IRQL to DISPATCH_LEVEL. Therefore, all accessed memory must be
      in non-paged pool.
--*/

#ifndef _RANSOMSHIELD_H_
#define _RANSOMSHIELD_H_

//
// ============================================================================
// BUILD CONFIGURATION
// ============================================================================
//

//
// Pull in the shared kernel/user-mode protocol types.
// fltkernel.h is always included by the .c files before RansomShield.h, so
// _FLTKERNEL_ will be defined and SharedDefs.h will take the kernel path.
//
#include "SharedDefs.h"

//
// Pool tag for all allocations. Used by Driver Verifier and pool tracking.
// 'RsSh' = RansomShield
//
#define RS_POOL_TAG             'hSsR'

//
// Minifilter name used for registration and communication port.
// Must match the name in the INF file's Instances section.
//
#define RS_FILTER_NAME          L"RansomShield"

//
// Altitude for this minifilter. Altitudes determine the order in which
// minifilters are invoked in the filter manager's stack.
//
// The 320000-329999 range is reserved for "Anti-Virus" filters per the
// Microsoft altitude allocation table. We choose 325010 which places us
// after encryption filters but before general scanning filters.
//
// Reference: https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
//
#define RS_ALTITUDE             L"325010"

//
// ============================================================================
// HEURISTIC THRESHOLD CONFIGURATION
// ============================================================================
//

//
// Compile-time defaults — used only to initialize the runtime globals in
// Context.c (g_FileCountThreshold, g_TimeWindowSeconds, g_TimeWindowTicks).
// After startup these can be overridden by the user-mode client.
//
#define RS_MODIFICATION_THRESHOLD       RS_DEFAULT_FILE_COUNT_THRESHOLD   // 50
#define RS_TIME_WINDOW_SECONDS          RS_DEFAULT_TIME_WINDOW_SECONDS     // 10
#define RS_TIME_WINDOW_TICKS            ((LONGLONG)RS_TIME_WINDOW_SECONDS * 10000000)

//
// Maximum number of process contexts we track simultaneously. This bounds
// memory usage in non-paged pool.
//
#define RS_MAX_TRACKED_PIDS             1024

//
// ============================================================================
// ALLOWLIST CONFIGURATION
// ============================================================================
//

// Number of entries in the hardcoded built-in static allowlist.
#define RS_ALLOWLIST_COUNT              10

//
// ============================================================================
// PER-PID TRACKING STRUCTURE
// ============================================================================
//

//
// RS_OPERATION_ENTRY - Records a single file modification event within
// the sliding window. We store the timestamp of each operation so that
// we can prune stale entries and compute the count within the window.
//
// Why store individual timestamps instead of just a count?
//   - A count-only approach cannot handle sliding windows accurately.
//     If we just increment a counter and reset it after 10 seconds,
//     a ransomware process could stay just below the threshold by
//     throttling slightly, then burst again after reset.
//   - Individual timestamps allow precise sliding window calculation:
//     count = number of entries where (current_time - timestamp < window).
//   - Memory cost: 8 bytes per entry * 50 max entries = 400 bytes per PID.
//     With 1024 PIDs, that's ~400KB of non-paged pool — acceptable.
//
typedef struct _RS_OPERATION_ENTRY {
    LONGLONG    Timestamp;          // KeQueryInterruptTime() value (100ns ticks)
} RS_OPERATION_ENTRY, *PRS_OPERATION_ENTRY;

//
// Maximum number of operation timestamps we store per PID before we
// stop recording (the PID is already flagged as malicious by then).
// This prevents unbounded memory growth from an extremely fast process.
//
#define RS_MAX_OPERATIONS_PER_PID       256

//
// RS_PROCESS_CONTEXT - Per-PID tracking structure. This is the core
// heuristic data structure. All instances are stored in a global
// hash table protected by a spinlock.
//
// MEMORY LIFECYCLE:
//   - Allocated via ExAllocatePool2(NonPagedPoolNx, ...) when a new
//     PID is first seen. NonPagedPoolNx is required because we access
//     this under a spinlock (IRQL raised to DISPATCH_LEVEL).
//   - Freed when the process exits (we detect this via a timer-based
//     garbage collection sweep) or during driver unload.
//
// SYNCHRONIZATION:
//   - The global hash table lock (g_ContextLock) protects the table
//     structure (insertions, deletions, lookups).
//   - Individual context fields are also protected by g_ContextLock
//     to keep the design simple. If finer-grained locking is needed
//     for performance, each context could have its own spinlock, but
//     the contention should be low for typical workloads.
//
typedef struct _RS_PROCESS_CONTEXT {
    //
    // Hash table link. We use separate chaining for collision resolution.
    //
    LIST_ENTRY      Link;

    //
    // The process ID this context tracks. We use the PID from
    // FltGetRequestorProcessId() which returns the real PID even
    // if the thread is impersonating (unlike PsGetCurrentProcessId).
    //
    ULONG           ProcessId;

    //
    // Image name of the process, captured at first sight. Used for
    // allowlist matching and telemetry. We capture this using
    // SeLocateProcessImageName() which returns a UNICODE_STRING
    // whose buffer is allocated from PAGED pool. We deep-copy the
    // name into this non-paged buffer so it can be accessed at
    // DISPATCH_LEVEL under the spinlock.
    //
    WCHAR           ImageName[RS_MAX_IMAGE_NAME_LEN];

    //
    // Ring buffer of operation timestamps. This is a circular buffer
    // where OperationHead points to the next slot to write, and
    // OperationCount tracks how many valid entries exist.
    //
    // Using a ring buffer avoids costly memmove operations when
    // pruning old entries. We simply advance the head pointer.
    //
    RS_OPERATION_ENTRY  Operations[RS_MAX_OPERATIONS_PER_PID];
    ULONG               OperationHead;     // Next write position (0..MAX-1)
    ULONG               OperationCount;    // Number of valid entries (0..MAX)

    //
    // Flag indicating this PID has been identified as malicious.
    // Once set, all subsequent write/rename/delete operations from
    // this PID are blocked with STATUS_ACCESS_DENIED.
    //
    // This flag is "sticky" — it is NOT automatically cleared when
    // operations fall below the threshold. A user-mode service must
    // explicitly unblock the PID via the communication port. This
    // prevents ransomware from simply waiting out the window.
    //
    BOOLEAN         IsBlocked;

    //
    // Timestamp when this process was first blocked. Used for
    // telemetry and for the user-mode service to display when the
    // detection occurred.
    //
    LONGLONG        BlockedTimestamp;

    //
    // Timestamp of the last operation recorded for this PID.
    // Used for LRU eviction when RS_MAX_TRACKED_PIDS is exceeded.
    //
    LONGLONG        LastActivityTime;

} RS_PROCESS_CONTEXT, *PRS_PROCESS_CONTEXT;

//
// ============================================================================
// USER-MODE COMMUNICATION PROTOCOL
// ============================================================================
//
// The communication port allows a user-mode service to:
//   1. Query the list of currently blocked PIDs
//   2. Unblock a specific PID (after admin confirmation)
//   3. Receive real-time alerts when a PID is newly blocked
//
// PROTOCOL DESIGN:
//   - All messages start with an RS_MESSAGE_HEADER containing a message
//     type and total size. This allows versioning and forward compat.
//   - User-mode sends RS_MESSAGE_HEADER (or larger struct) via
//     FilterSendMessage().
//   - Kernel-mode replies via FilterReplyMessage().
//   - Kernel-mode can also push notifications to the user-mode port
//     via FltSendMessage() when a new PID is blocked.
//
// IMPORTANT: The user-mode client MUST use FilterGetMessage() to
// receive unsolicited notifications from the kernel. The client should
// have a dedicated thread calling FilterGetMessage() in a loop.
//

// ============================================================================
// GLOBAL STATE DECLARATIONS
// ============================================================================
//

extern PFLT_FILTER g_FilterHandle;
extern PFLT_PORT   g_ServerPort;
extern PFLT_PORT   g_ClientPort;

#define RS_HASH_TABLE_SIZE      1021    // Prime number for good distribution

extern LIST_ENTRY  g_ContextHashTable[RS_HASH_TABLE_SIZE];
extern KSPIN_LOCK  g_ContextLock;
extern ULONG       g_TrackedPidCount;
extern ULONG       g_MessageSequence;

// Runtime-configurable heuristic parameters (initialized from SharedDefs.h defaults).
// Protected by g_ContextLock for both reads and writes.
extern ULONG       g_FileCountThreshold;
extern ULONG       g_TimeWindowSeconds;
extern LONGLONG    g_TimeWindowTicks;
extern BOOLEAN     g_MonitoringEnabled;

// Dynamic allowlist (user-mode push, in addition to the static built-in list).
// Array of null-terminated wide strings, protected by g_ContextLock.
extern WCHAR       g_DynamicAllowlist[RS_MAX_ALLOWLIST_ENTRIES][RS_MAX_ALLOWLIST_NAME_LEN];
extern ULONG       g_DynamicAllowlistCount;

// Static built-in allowlist (compile-time, in .rdata — safe at DISPATCH_LEVEL).
extern UNICODE_STRING g_Allowlist[RS_ALLOWLIST_COUNT];

//
// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================
//

//
// --- RansomShield.c (Main driver entry, filter registration, callbacks) ---
//

DRIVER_INITIALIZE               DriverEntry;

//
// FilterUnloadCallback - Called when the minifilter is about to be unloaded.
// Must clean up all resources: communication ports, contexts, locks.
//
FLT_PREOP_CALLBACK_STATUS
RsPreOperationWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
RsPreOperationSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
RsPostOperationSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS
RsUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

//
// --- Context.c (Per-PID tracking and heuristic evaluation) ---
//

NTSTATUS
RsInitializeContextTracking(
    VOID
    );

VOID
RsDestroyContextTracking(
    VOID
    );

NTSTATUS
RsRecordOperation(
    _In_ ULONG ProcessId,
    _In_ PUNICODE_STRING ProcessImageName,
    _Out_ PBOOLEAN ShouldBlock
    );

VOID
RsPruneOldOperations(
    _Inout_ PRS_PROCESS_CONTEXT Context,
    _In_ LONGLONG CurrentTime
    );

VOID
RsRemoveProcessContext(
    _In_ ULONG ProcessId
    );

VOID
RsUnblockProcess(
    _In_ ULONG ProcessId
    );

VOID
RsGetBlockedPids(
    _Out_writes_to_(MaxEntries, *CountReturned) PRS_BLOCKED_PID_ENTRY Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG CountReturned
    );

VOID
RsGetPidCounts(
    _Out_ PULONG TrackedCount,
    _Out_ PULONG BlockedCount
    );

BOOLEAN
RsIsProcessAllowlisted(
    _In_ PUNICODE_STRING ProcessImageName
    );

VOID
RsApplyConfig(
    _In_ ULONG FileCountThreshold,
    _In_ ULONG TimeWindowSeconds,
    _In_ BOOLEAN MonitoringEnabled
    );

VOID
RsClearDynamicAllowlist(
    VOID
    );

VOID
RsAddDynamicAllowlistEntry(
    _In_reads_(EntryLen) PWCHAR Entry,
    _In_ ULONG EntryLen
    );

//
// --- CommPort.c (User-mode communication port) ---
//

NTSTATUS
RsInitializeCommPort(
    _In_ PFLT_FILTER FilterHandle
    );

VOID
RsDestroyCommPort(
    VOID
    );

NTSTATUS
RsSendBlockNotification(
    _In_ ULONG ProcessId,
    _In_ PWCHAR ImageName,
    _In_ LONGLONG BlockedTimestamp,
    _In_ ULONG OperationCount
    );

//
// Communication port callbacks - called by the filter manager.
//
NTSTATUS
RsConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

VOID
RsDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
RsMessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

#endif /* _RANSOMSHIELD_H_ */
