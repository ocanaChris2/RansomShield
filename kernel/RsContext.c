/*++
Module Name:
    RsContext.c

Abstract:
    Per-PID heuristic tracking module for the RansomShield minifilter driver.
    This module implements a spinlock-protected hash table that tracks file
    modification counts per process using a sliding time window algorithm.

    DESIGN PHILOSOPHY:
    - All data structures reside in NonPagedPoolNx (No-Execute non-paged pool)
      because they are accessed under a spinlock which raises IRQL to
      DISPATCH_LEVEL. At DISPATCH_LEVEL, accessing paged memory causes a
      BUGCHECK (IRQL_NOT_LESS_OR_EQUAL).
    - We use a single global spinlock for the entire hash table rather than
      per-bucket locks. This simplifies the design and reduces memory overhead.
      Contention should be minimal because:
        (a) The critical section under the lock is very short (pointer ops,
            counter increments, timestamp comparisons).
        (b) File I/O pre-callbacks are inherently serialized per-file by the
            filter manager for a given minifilter.
    - We use KeAcquireSpinLock / KeReleaseSpinLock which raise IRQL to
      DISPATCH_LEVEL. We store the old IRQL and restore it on release.
      This is the correct pattern for code that may be called at
      PASSIVE_LEVEL or APC_LEVEL.

    HASH TABLE LAYOUT:
    ┌──────────┐
    │ Bucket 0 │──► Context A ──► Context B ──► NULL
    ├──────────┤
    │ Bucket 1 │──► NULL
    ├──────────┤
    │ Bucket 2 │──► Context C ──► NULL
    ├──────────┤
    │   ...    │
    └──────────┘

    COLLISION RESOLUTION: Separate chaining via LIST_ENTRY links.
    HASH FUNCTION: ProcessId % RS_HASH_TABLE_SIZE (1021, a prime).

Author:
    RansomShield Development

Environment:
    Kernel mode, IRQL <= DISPATCH_LEVEL when accessing table entries
--*/

#include <fltkernel.h>
#include "RansomShield.h"

//
// ============================================================================
// GLOBAL STATE
// ============================================================================
//

//
// Hash table buckets. Each bucket is a LIST_ENTRY that serves as the
// list head for contexts that hash to that bucket. LIST_ENTRY is used
// (rather than a singly-linked list) because it supports O(1) removal
// of an arbitrary element without traversing the list.
//
LIST_ENTRY  g_ContextHashTable[RS_HASH_TABLE_SIZE];

//
// Global spinlock protecting the entire hash table and all context
// structures within it. Acquired before any read or write to the table.
//
// IRQL NOTE: KeAcquireSpinLock raises IRQL to DISPATCH_LEVEL and stores
// the previous IRQL in the KIRQL output parameter. KeReleaseSpinLock
// restores the previous IRQL. This means:
//   - While the lock is held, no page faults can occur (DISPATCH_LEVEL).
//   - All memory touched MUST be non-paged.
//   - No blocking waits, no mutex acquisitions, no paged API calls.
//
KSPIN_LOCK  g_ContextLock;

//
// Current count of tracked PIDs. Protected by g_ContextLock.
// Used to enforce RS_MAX_TRACKED_PIDS limit and for telemetry.
//
ULONG       g_TrackedPidCount = 0;

//
// Monotonically increasing message sequence number for communication port.
// Protected by g_ContextLock (avoids needing a separate lock).
//
ULONG       g_MessageSequence = 0;

//
// Runtime-configurable heuristic parameters.  All protected by g_ContextLock.
// Initialized from the SharedDefs.h defaults; overwritten by UpdateConfig messages.
//
ULONG    g_FileCountThreshold = RS_DEFAULT_FILE_COUNT_THRESHOLD;
ULONG    g_TimeWindowSeconds  = RS_DEFAULT_TIME_WINDOW_SECONDS;
LONGLONG g_TimeWindowTicks    = (LONGLONG)RS_DEFAULT_TIME_WINDOW_SECONDS * 10000000LL;
BOOLEAN  g_MonitoringEnabled  = RS_DEFAULT_MONITORING_ENABLED;

//
// Dynamic allowlist populated at runtime via user-mode push messages.
// Entries are null-terminated wide strings.  Protected by g_ContextLock.
// Resides in the driver image's .data section — always non-paged.
//
WCHAR g_DynamicAllowlist[RS_MAX_ALLOWLIST_ENTRIES][RS_MAX_ALLOWLIST_NAME_LEN];
ULONG g_DynamicAllowlistCount = 0;

//
// Static built-in allowlist: UNICODE_STRINGs pointing into .rdata literals.
//
UNICODE_STRING g_Allowlist[RS_ALLOWLIST_COUNT];

//
// Static wide-string literals for the allowlist. These are placed in
// the driver image's read-only data section, which is always non-paged.
//
static const WCHAR g_AllowList_Names[RS_ALLOWLIST_COUNT][RS_MAX_IMAGE_NAME_LEN] = {
    L"svchost.exe",
    L"SearchIndexer.exe",
    L"MsMpEng.exe",
    L"TrustedInstaller.exe",
    L"System",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"services.exe",
    L"dwm.exe"
};

// ============================================================================
// FORWARD DECLARATIONS (internal helpers)
// ============================================================================

static
PRS_PROCESS_CONTEXT
RsLookupProcessContext(
    _In_ ULONG ProcessId,
    _Out_ PLIST_ENTRY *BucketHead
    );

static
PRS_PROCESS_CONTEXT
RsCreateProcessContext(
    _In_ ULONG ProcessId,
    _In_opt_ PUNICODE_STRING ProcessImageName
    );

static
ULONG
RsHashProcessId(
    _In_ ULONG ProcessId
    );

static
VOID
RsCopyImageNameToContext(
    _Inout_ PRS_PROCESS_CONTEXT Context,
    _In_opt_ PUNICODE_STRING SourceName
    );

// ============================================================================
// INITIALIZATION / TEARDOWN
// ============================================================================

/*++
Routine Description:
    Initializes the per-PID context tracking subsystem. Must be called
    exactly once during DriverEntry before any filter operations occur.

    Operations performed:
    1. Initialize the spinlock (KeInitializeSpinLock).
    2. Initialize all hash table bucket list heads (InitializeListHead).
    3. Initialize the allowlist UNICODE_STRING pointers.

Return Value:
    STATUS_SUCCESS on success. This routine cannot fail as it only
    initializes in-memory structures with no allocations.
--*/
NTSTATUS
RsInitializeContextTracking(
    VOID
    )
{
    ULONG i;

    //
    // Initialize the global spinlock. KeInitializeSpinLock sets the
    // spinlock to the "not acquired" state. This must be called before
    // any KeAcquireSpinLock calls. It is safe to call at any IRQL.
    //
    KeInitializeSpinLock(&g_ContextLock);

    //
    // Initialize each hash table bucket as an empty list.
    // InitializeListHead sets Flink = Blink = &Head, indicating an
    // empty circular doubly-linked list.
    //
    for (i = 0; i < RS_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&g_ContextHashTable[i]);
    }

    //
    // Initialize the allowlist. We point each UNICODE_STRING to the
    // corresponding static string literal. These are in the driver's
    // .rdata section, which is non-pageable and always accessible.
    //
    // We use RtlInitUnicodeString which sets Length and MaximumLength
    // based on wcslen(). The Buffer pointer points to the static string.
    //
    for (i = 0; i < RS_ALLOWLIST_COUNT; i++) {
        RtlInitUnicodeString(&g_Allowlist[i], g_AllowList_Names[i]);
    }

    g_TrackedPidCount = 0;
    g_MessageSequence = 0;

    return STATUS_SUCCESS;
}

/*++
Routine Description:
    Destroys all context tracking data. Must be called during
    FilterUnloadCallback after all I/O has been drained.

    IMPORTANT: This must be called when NO pre/post callbacks are
    executing. The filter manager guarantees this because it waits
    for all outstanding callbacks to complete before calling the
    unload routine. Therefore, we don't need to acquire the spinlock
    here — there should be no concurrent access.

    However, for defensive programming, we still acquire the lock
    to guard against programming errors.
--*/
VOID
RsDestroyContextTracking(
    VOID
    )
{
    KIRQL oldIrql;
    ULONG i;
    PLIST_ENTRY listHead;
    PLIST_ENTRY entry;
    PRS_PROCESS_CONTEXT context;

    KeAcquireSpinLock(&g_ContextLock, &oldIrql);

    for (i = 0; i < RS_HASH_TABLE_SIZE; i++) {
        listHead = &g_ContextHashTable[i];

        //
        // Walk the chain and free each context structure.
        // RemoveHeadList removes the first entry and returns it.
        // We keep removing until the list is empty.
        //
        while (!IsListEmpty(listHead)) {
            entry = RemoveHeadList(listHead);
            context = CONTAINING_RECORD(entry, RS_PROCESS_CONTEXT, Link);

            //
            // Free the context structure. It was allocated with
            // ExAllocatePool2(NonPagedPoolNx, ...) in RsCreateProcessContext.
            //
            // ExFreePoolWithTag is safe to call at DISPATCH_LEVEL because
            // it operates on non-paged pool.
            //
            ExFreePoolWithTag(context, RS_POOL_TAG);
        }
    }

    g_TrackedPidCount = 0;

    KeReleaseSpinLock(&g_ContextLock, oldIrql);
}

// ============================================================================
// HASH FUNCTION
// ============================================================================

/*++
Routine Description:
    Simple hash function mapping a ProcessId to a hash table bucket index.

    We use modulo with a prime number (1021). PIDs on Windows are typically
    multiples of 4, so using a power-of-2 table size would cause clustering
    in specific buckets. A prime number distributes the remainders more
    evenly.

    For a more robust hash in production, consider using a multiplicative
    hash: (ProcessId * 2654435761) >> shift, where the constant is derived
    from the golden ratio. But for our purposes, modulo is sufficient.
--*/
static
ULONG
RsHashProcessId(
    _In_ ULONG ProcessId
    )
{
    return ProcessId % RS_HASH_TABLE_SIZE;
}

// ============================================================================
// CONTEXT LOOKUP
// ============================================================================

/*++
Routine Description:
    Looks up a process context by PID in the hash table.

    IRQL: Caller must hold g_ContextLock (DISPATCH_LEVEL).

    Parameters:
        ProcessId   - The PID to search for.
        BucketHead  - [out] Receives a pointer to the bucket's LIST_ENTRY
                      head. This allows the caller to insert a new context
                      into the correct bucket without recomputing the hash.

Return Value:
    Pointer to the RS_PROCESS_CONTEXT if found, NULL otherwise.
--*/
static
PRS_PROCESS_CONTEXT
RsLookupProcessContext(
    _In_ ULONG ProcessId,
    _Out_ PLIST_ENTRY *BucketHead
    )
{
    ULONG hashIndex;
    PLIST_ENTRY listHead;
    PLIST_ENTRY entry;
    PRS_PROCESS_CONTEXT context;

    hashIndex = RsHashProcessId(ProcessId);
    listHead = &g_ContextHashTable[hashIndex];

    //
    // Return the bucket head so the caller can use it for insertion
    // if the context doesn't exist.
    //
    *BucketHead = listHead;

    //
    // Walk the chain at this bucket. For each entry, use
    // CONTAINING_RECORD to recover the RS_PROCESS_CONTEXT from
    // its Link field.
    //
    for (entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
        context = CONTAINING_RECORD(entry, RS_PROCESS_CONTEXT, Link);
        if (context->ProcessId == ProcessId) {
            return context;
        }
    }

    return NULL;
}

// ============================================================================
// CONTEXT CREATION
// ============================================================================

/*++
Routine Description:
    Allocates and initializes a new RS_PROCESS_CONTEXT for the given PID.

    IMPORTANT IRQL NOTE:
        This function is called from RsRecordOperation which holds
        g_ContextLock at DISPATCH_LEVEL. Therefore, we CANNOT call
        ExAllocatePool2 here because it may need to acquire the pool
        mutex (which requires PASSIVE_LEVEL).

        SOLUTION: The caller (RsRecordOperation) allocates the context
        BEFORE acquiring the spinlock, then inserts it under the lock.
        This function should only be called when the lock is NOT held.

        ALTERNATIVE: We could use a look-aside list (ExInitializeLookasideListEx)
        which pre-allocates entries and can be accessed at DISPATCH_LEVEL.
        However, for simplicity and since we expect low allocation rates,
        we allocate at PASSIVE_LEVEL before acquiring the lock.

    Actually, let's reconsider: RsRecordOperation is called from a
    pre-operation callback which runs at PASSIVE_LEVEL or APC_LEVEL.
    We CAN acquire and release the spinlock multiple times within the
    same callback. So we can:
        1. Acquire spinlock, lookup context.
        2. If not found, release spinlock, allocate, re-acquire, insert.
        3. Record the operation.

    But this creates a race: two threads could both find the context
    missing and both allocate. The second insertion would need to check
    again. To simplify, we allocate optimistically before taking the lock,
    and free the allocation if another thread won the race.

--*/
static
PRS_PROCESS_CONTEXT
RsCreateProcessContext(
    _In_ ULONG ProcessId,
    _In_opt_ PUNICODE_STRING ProcessImageName
    )
{
    PRS_PROCESS_CONTEXT context;

    //
    // Allocate from NonPagedPoolNx (No-Execute non-paged pool).
    //
    // WHY NonPagedPoolNx?
    //   1. NonPaged: This memory is accessed under a spinlock at
    //      DISPATCH_LEVEL. Paged memory would cause a BUGCHECK.
    //   2. No-Execute (Nx): Data structures should never be executed.
    //      NX pool is the default for Windows 10+ and is required by
    //      HVCI (Hypervisor-Enforced Code Integrity). Using NonPagedPool
    //      (without Nx) may fail on HVCI-enabled systems.
    //
    // ExAllocatePool2 is the preferred API for Windows 10+ (WDK 2004+).
    // It zero-initializes the allocation (POOL_FLAG_NON_PAGED_POOL_NX
    // implies zero-fill), preventing information leaks from previous
    // allocations.
    //
    // For older WDKs, use:
    //   ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(RS_PROCESS_CONTEXT), RS_POOL_TAG);
    //   RtlZeroMemory(context, sizeof(RS_PROCESS_CONTEXT));
    //
    context = (PRS_PROCESS_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,  // Non-executable non-paged pool (HVCI-safe)
        sizeof(RS_PROCESS_CONTEXT),
        RS_POOL_TAG
    );

    if (context == NULL) {
        //
        // Allocation failure. In kernel mode, this is serious but
        // not fatal for this driver — we simply won't track this PID,
        // and operations will be allowed through. We log the failure
        // via DbgPrint (production code would use ETW/WPP tracing).
        //
        DbgPrint("RansomShield: Failed to allocate context for PID %lu\n", ProcessId);
        return NULL;
    }

    //
    // Initialize the context fields. ExAllocatePool2 zero-fills, so
    // all counters and flags are already 0/FALSE.
    //
    context->ProcessId = ProcessId;
    context->OperationHead = 0;
    context->OperationCount = 0;
    context->IsBlocked = FALSE;
    context->BlockedTimestamp = 0;
    context->LastActivityTime = 0;
    InitializeListHead(&context->Link);

    //
    // Copy the image name into the context. We make a deep copy because
    // the source UNICODE_STRING's buffer may be in paged memory (from
    // SeLocateProcessImageName) and we need non-paged access.
    //
    RsCopyImageNameToContext(context, ProcessImageName);

    return context;
}

/*++
Routine Description:
    Copies the image name from a UNICODE_STRING into the fixed-size
    WCHAR array in a process context. Handles truncation gracefully.

    WHY DEEP COPY?
    - The UNICODE_STRING buffer from SeLocateProcessImageName() points
      to memory in the EPROCESS structure's quota block, which may be
      in paged pool.
    - Our context is in non-paged pool and may be accessed at DISPATCH_LEVEL.
    - Therefore, we must copy the string data into our own non-paged buffer.
--*/
static
VOID
RsCopyImageNameToContext(
    _Inout_ PRS_PROCESS_CONTEXT Context,
    _In_opt_ PUNICODE_STRING SourceName
    )
{
    ULONG copyChars;

    if (SourceName == NULL || SourceName->Buffer == NULL) {
        //
        // No image name available. Leave the context's ImageName as
        // all zeros (already zero-filled by ExAllocatePool2).
        //
        Context->ImageName[0] = L'\0';
        return;
    }

    //
    // Calculate how many characters we can copy, excluding the null
    // terminator. SourceName->Length is in BYTES (not characters),
    // so we divide by sizeof(WCHAR).
    //
    copyChars = SourceName->Length / sizeof(WCHAR);

    if (copyChars >= RS_MAX_IMAGE_NAME_LEN) {
        copyChars = RS_MAX_IMAGE_NAME_LEN - 1;  // Leave room for null terminator
    }

    //
    // Copy the relevant portion and null-terminate.
    //
    // RtlCopyMemory is the kernel-mode equivalent of memcpy. It's safe
    // at DISPATCH_LEVEL because both buffers are in non-paged pool.
    //
    RtlCopyMemory(Context->ImageName, SourceName->Buffer, copyChars * sizeof(WCHAR));
    Context->ImageName[copyChars] = L'\0';
}

// ============================================================================
// CORE HEURISTIC LOGIC
// ============================================================================

/*++
Routine Description:
    Records a file modification operation for the given process and
    evaluates the heuristic threshold. This is the PRIMARY entry point
    called from pre-operation callbacks.

    ALGORITHM:
    1. If the PID is already blocked, set ShouldBlock = TRUE and return.
    2. Look up (or create) the per-PID context.
    3. Prune operations outside the sliding time window.
    4. Record the new operation timestamp.
    5. Check if the operation count exceeds RS_MODIFICATION_THRESHOLD.
    6. If so, mark the PID as blocked and set ShouldBlock = TRUE.
    7. Send a notification to the user-mode service (if connected).

    SYNCHRONIZATION STRATEGY:
    To avoid allocating memory under a spinlock, we use an optimistic
    allocation pattern:
      - First lookup: Acquire spinlock, check if context exists.
        If yes, record the operation under the lock.
      - If not found: Release spinlock, allocate context (at PASSIVE_LEVEL),
        re-acquire spinlock, check again (another thread may have created it),
        insert if still missing, then record the operation.

    This "double-checked locking" pattern is safe because:
      - The worst case is a wasted allocation (freed immediately).
      - It ensures we never call ExAllocatePool2 at DISPATCH_LEVEL.
      - The race window is tiny and the cost of a rare extra allocation
        is negligible.

    IRQL: Called at PASSIVE_LEVEL or APC_LEVEL (pre-callback context).

    Parameters:
        ProcessId           - PID from FltGetRequestorProcessId()
        ProcessImageName    - Image name of the process (may be NULL)
        ShouldBlock         - [out] TRUE if the PID should be blocked

Return Value:
    STATUS_SUCCESS if tracking succeeded (even if ShouldBlock = FALSE).
    STATUS_INSUFFICIENT_RESOURCES if context allocation failed.
--*/
NTSTATUS
RsRecordOperation(
    _In_ ULONG ProcessId,
    _In_opt_ PUNICODE_STRING ProcessImageName,
    _Out_ PBOOLEAN ShouldBlock
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY bucketHead;
    PRS_PROCESS_CONTEXT context;
    PRS_PROCESS_CONTEXT newContext = NULL;
    LONGLONG currentTime;
    ULONG recentCount;

    *ShouldBlock = FALSE;

    //
    // Get the current time. KeQueryInterruptTime() returns a monotonically
    // increasing 64-bit value in 100-nanosecond intervals. It's safe to
    // call at any IRQL and is more efficient than KeQuerySystemTime()
    // because it doesn't require a system call — it reads a per-CPU
    // tick counter.
    //
    // We use this instead of KeQuerySystemTime() because:
    //   1. It's faster (no system call).
    //   2. It's monotonically increasing (no time zone or NTP adjustments).
    //   3. It's safe at any IRQL.
    //
    currentTime = KeQueryInterruptTime();

    //
    // ---- FIRST LOOKUP (under lock) ----
    // Try to find the existing context under the spinlock.
    //
    KeAcquireSpinLock(&g_ContextLock, &oldIrql);

    context = RsLookupProcessContext(ProcessId, &bucketHead);

    if (context != NULL) {
        //
        // Context exists. Check if already blocked.
        //
        if (context->IsBlocked) {
            *ShouldBlock = TRUE;
            KeReleaseSpinLock(&g_ContextLock, oldIrql);
            return STATUS_SUCCESS;
        }

        //
        // Context exists and is not blocked. Record the operation.
        // We can do this under the lock since it's just pointer/counter ops.
        //
        goto RecordAndEvaluate;
    }

    //
    // Context does not exist. We need to create one, but we can't
    // allocate memory while holding a spinlock (ExAllocatePool2 may
    // need to acquire the pool mutex at PASSIVE_LEVEL).
    //
    // Release the lock, allocate, then re-acquire and re-check.
    //
    KeReleaseSpinLock(&g_ContextLock, oldIrql);

    //
    // ---- ALLOCATION (at PASSIVE_LEVEL, no lock held) ----
    //

    //
    // Check if we've reached the maximum number of tracked PIDs.
    // If so, we need to evict the least recently active context.
    // For simplicity, we allow a small overrun here and evict lazily.
    // A production driver would implement LRU eviction.
    //
    newContext = RsCreateProcessContext(ProcessId, ProcessImageName);
    if (newContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // ---- SECOND LOOKUP (under lock, with pre-allocated context) ----
    // Re-acquire the lock and check if another thread created the context
    // while we were allocating. This is the "double-checked locking" pattern.
    //
    KeAcquireSpinLock(&g_ContextLock, &oldIrql);

    context = RsLookupProcessContext(ProcessId, &bucketHead);

    if (context != NULL) {
        //
        // Another thread won the race. Free our allocation and use theirs.
        // ExFreePoolWithTag is safe at DISPATCH_LEVEL for non-paged pool.
        //
        ExFreePoolWithTag(newContext, RS_POOL_TAG);

        if (context->IsBlocked) {
            *ShouldBlock = TRUE;
            KeReleaseSpinLock(&g_ContextLock, oldIrql);
            return STATUS_SUCCESS;
        }
    } else {
        //
        // Our allocation wins. Insert the new context into the hash table.
        //
        context = newContext;

        //
        // Insert at the HEAD of the bucket chain. InsertHeadList is O(1).
        // This is more cache-friendly than InsertTailList for frequently
        // accessed entries (temporal locality).
        //
        InsertHeadList(bucketHead, &context->Link);
        g_TrackedPidCount++;
    }

RecordAndEvaluate:

    //
    // ---- PRUNE OLD OPERATIONS ----
    // Remove operation timestamps that fall outside the sliding window.
    // This ensures our count reflects only recent activity.
    //
    RsPruneOldOperations(context, currentTime);

    //
    // ---- RECORD NEW OPERATION ----
    // Add the current operation's timestamp to the ring buffer.
    //
    if (context->OperationCount < RS_MAX_OPERATIONS_PER_PID) {
        //
        // The ring buffer is not yet full. Simple append.
        //
        context->Operations[context->OperationHead].Timestamp = currentTime;
        context->OperationHead = (context->OperationHead + 1) % RS_MAX_OPERATIONS_PER_PID;
        context->OperationCount++;
    } else {
        //
        // Ring buffer is full. Overwrite the oldest entry (at OperationHead,
        // which wraps around to the oldest slot). This is correct because
        // OperationHead has already advanced past all valid entries.
        //
        // When the buffer is full, OperationHead points to the OLDEST entry
        // (the one about to be overwritten). After writing, we advance.
        //
        context->Operations[context->OperationHead].Timestamp = currentTime;
        context->OperationHead = (context->OperationHead + 1) % RS_MAX_OPERATIONS_PER_PID;
    }

    //
    // Update last activity timestamp for LRU eviction.
    //
    context->LastActivityTime = currentTime;

    //
    // ---- EVALUATE THRESHOLD ----
    // Count operations within the sliding window.
    //
    // After pruning, OperationCount reflects only recent operations.
    // But pruning may have been imperfect (it only removes from the
    // tail of the ring buffer). We do a precise count here.
    //
    recentCount = 0;
    if (context->OperationCount > 0) {
        ULONG idx;
        ULONG i;
        ULONG count;

        //
        // Walk the ring buffer and count entries within the time window.
        // The oldest entry is at index:
        //   (OperationHead - OperationCount + MAX) % MAX
        // (Because OperationHead points to the NEXT write position, and
        // OperationCount entries precede it in the ring.)
        //
        idx = (context->OperationHead + RS_MAX_OPERATIONS_PER_PID - context->OperationCount)
              % RS_MAX_OPERATIONS_PER_PID;

        count = context->OperationCount;
        for (i = 0; i < count; i++) {
            if ((currentTime - context->Operations[idx].Timestamp) <= g_TimeWindowTicks) {
                recentCount++;
            }
            idx = (idx + 1) % RS_MAX_OPERATIONS_PER_PID;
        }
    }

    //
    // ---- THRESHOLD CHECK ----
    //
    // LOCAL STORAGE for post-lock notification:
    // We must copy any data needed after releasing the spinlock into
    // local (stack) variables. Once we release g_ContextLock, another
    // thread can call RsUnblockProcess() which frees the context via
    // RsRemoveProcessContext() → ExFreePoolWithTag, leaving the
    // 'context' pointer dangling. Accessing context->ImageName or
    // context->BlockedTimestamp after releasing the lock would be a
    // USE-AFTER-FREE bug.
    //
    WCHAR localImageName[RS_MAX_IMAGE_NAME_LEN];
    LONGLONG localBlockedTimestamp = 0;
    BOOLEAN localShouldNotify = FALSE;

    if (recentCount >= g_FileCountThreshold && !context->IsBlocked && g_MonitoringEnabled) {
        //
        // THRESHOLD EXCEEDED! Mark this PID as malicious.
        //
        // The IsBlocked flag is "sticky" — it stays TRUE until explicitly
        // cleared by the user-mode service via RsUnblockProcess(). This
        // prevents ransomware from simply waiting out the time window and
        // then resuming encryption.
        //
        context->IsBlocked = TRUE;
        context->BlockedTimestamp = currentTime;
        *ShouldBlock = TRUE;
        localShouldNotify = TRUE;

        //
        // Copy notification data to local storage BEFORE releasing the lock.
        // Both source (context->ImageName, in non-paged pool) and destination
        // (stack) are accessible at DISPATCH_LEVEL. RtlCopyMemory is safe.
        //
        RtlCopyMemory(localImageName, context->ImageName, sizeof(localImageName));
        localBlockedTimestamp = context->BlockedTimestamp;

        if (ProcessImageName != NULL) {
            DbgPrint("RansomShield: PID %lu (%wZ) BLOCKED - %lu ops in %d sec window\n",
                     ProcessId, ProcessImageName, recentCount, RS_TIME_WINDOW_SECONDS);
        } else {
            DbgPrint("RansomShield: PID %lu (unknown) BLOCKED - %lu ops in %d sec window\n",
                     ProcessId, recentCount, RS_TIME_WINDOW_SECONDS);
        }
    }

    KeReleaseSpinLock(&g_ContextLock, oldIrql);

    //
    // ---- SEND NOTIFICATION (at PASSIVE_LEVEL, no lock held) ----
    // If we just blocked a PID, notify the user-mode service.
    // FltSendMessage() can only be called at PASSIVE_LEVEL because
    // it may wait for the user-mode client to read the message.
    //
    // We use the locally-copied data, NOT the context pointer, because
    // the context may have been freed by another thread between the
    // KeReleaseSpinLock above and this point.
    //
    if (localShouldNotify) {
        RsSendBlockNotification(
            ProcessId,
            localImageName,
            localBlockedTimestamp,
            recentCount
        );
    }

    return STATUS_SUCCESS;
}

/*++
Routine Description:
    Prunes operation timestamps that have fallen outside the sliding
    time window. This is called under the spinlock.

    We use a temporary buffer to avoid the wrap-around compaction bug.
    In-place compaction of a ring buffer is dangerous because when the
    ring wraps around, reading from a later position and writing to an
    earlier position can overwrite entries that haven't been read yet.

    FIX: We compact into a temporary stack buffer, then copy back.
    This is O(n) in time and O(n) in stack space, but with
    RS_MAX_OPERATIONS_PER_PID = 256 and sizeof(RS_OPERATION_ENTRY) = 8,
    the temp buffer is only 2KB — well within kernel stack limits
    (typically 12KB-24KB depending on the OS version).

    IRQL: Called at DISPATCH_LEVEL (under g_ContextLock).
--*/
VOID
RsPruneOldOperations(
    _Inout_ PRS_PROCESS_CONTEXT Context,
    _In_ LONGLONG CurrentTime
    )
{
    RS_OPERATION_ENTRY tempBuffer[RS_MAX_OPERATIONS_PER_PID];
    ULONG readIdx;
    ULONG newCount;
    ULONG i;

    if (Context->OperationCount == 0) {
        return;
    }

    //
    // Start reading from the oldest entry in the ring buffer.
    //
    readIdx = (Context->OperationHead + RS_MAX_OPERATIONS_PER_PID - Context->OperationCount)
              % RS_MAX_OPERATIONS_PER_PID;

    newCount = 0;

    //
    // Scan the ring buffer and copy recent entries into the temp buffer.
    // The temp buffer is a simple linear array (no wrap-around), so
    // compaction is straightforward: copy entries that are within the
    // time window, skip entries that are too old.
    //
    for (i = 0; i < Context->OperationCount; i++) {
        LONGLONG age = CurrentTime - Context->Operations[readIdx].Timestamp;

        if (age <= g_TimeWindowTicks) {
            //
            // Entry is within the window. Keep it.
            //
            tempBuffer[newCount] = Context->Operations[readIdx];
            newCount++;
        }
        //
        // else: Entry is too old. Skip it (effectively removes it).
        //

        readIdx = (readIdx + 1) % RS_MAX_OPERATIONS_PER_PID;
    }

    //
    // Copy the compacted entries back from the temp buffer to the
    // ring buffer. After compaction, the ring buffer is treated as
    // a simple linear array from index 0 to newCount-1, with
    // OperationHead pointing just past the last entry.
    //
    if (newCount > 0) {
        RtlCopyMemory(Context->Operations, tempBuffer, newCount * sizeof(RS_OPERATION_ENTRY));
    }

    Context->OperationCount = newCount;
    Context->OperationHead = newCount % RS_MAX_OPERATIONS_PER_PID;
}

// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

/*++
Routine Description:
    Removes a process context from the hash table and frees it.
    Used when a process exits or when the user-mode service requests
    an unblock (which also removes the tracking data).

    IRQL: Acquires g_ContextLock internally. Must be called at
          PASSIVE_LEVEL or APC_LEVEL.
--*/
VOID
RsRemoveProcessContext(
    _In_ ULONG ProcessId
    )
{
    KIRQL oldIrql;
    PLIST_ENTRY bucketHead;
    PRS_PROCESS_CONTEXT context;

    KeAcquireSpinLock(&g_ContextLock, &oldIrql);

    context = RsLookupProcessContext(ProcessId, &bucketHead);

    if (context != NULL) {
        //
        // Remove from the hash table chain and free the memory.
        // RemoveEntryList removes the entry from its list and
        // reinitializes its Flink/Blink to point to itself.
        //
        RemoveEntryList(&context->Link);
        g_TrackedPidCount--;

        ExFreePoolWithTag(context, RS_POOL_TAG);
    }

    KeReleaseSpinLock(&g_ContextLock, oldIrql);
}

/*++
Routine Description:
    Unblocks a previously blocked PID. Called from the communication
    port message handler when the user-mode service confirms the PID
    should be allowed again.

    This simply removes the process context entirely, resetting its
    operation count. An alternative design would just clear IsBlocked,
    but removing the context is simpler and avoids stale data.

    IRQL: Called from the communication port message callback at
          PASSIVE_LEVEL.
--*/
VOID
RsUnblockProcess(
    _In_ ULONG ProcessId
    )
{
    RsRemoveProcessContext(ProcessId);
}

/*++
Routine Description:
    Collects all currently blocked PIDs into a caller-supplied buffer.
    Used by the communication port message handler to respond to
    user-mode queries.

    IRQL: Acquires g_ContextLock internally. Must be called at
          PASSIVE_LEVEL or APC_LEVEL.
--*/
VOID
RsGetBlockedPids(
    _Out_writes_to_(MaxEntries, *CountReturned) PRS_BLOCKED_PID_ENTRY Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG CountReturned
    )
{
    KIRQL oldIrql;
    ULONG i;
    PLIST_ENTRY listHead;
    PLIST_ENTRY entry;
    PRS_PROCESS_CONTEXT context;
    ULONG count = 0;

    *CountReturned = 0;

    KeAcquireSpinLock(&g_ContextLock, &oldIrql);

    for (i = 0; i < RS_HASH_TABLE_SIZE && count < MaxEntries; i++) {
        listHead = &g_ContextHashTable[i];

        for (entry = listHead->Flink; entry != listHead && count < MaxEntries; entry = entry->Flink) {
            context = CONTAINING_RECORD(entry, RS_PROCESS_CONTEXT, Link);

            if (context->IsBlocked) {
                Entries[count].ProcessId = context->ProcessId;
                Entries[count].BlockedTimestamp = context->BlockedTimestamp;
                Entries[count].OperationCount = context->OperationCount;

                //
                // Copy the image name. Both source and destination are
                // in non-paged pool, so RtlCopyMemory is safe at DISPATCH_LEVEL.
                //
                RtlCopyMemory(Entries[count].ImageName, context->ImageName,
                              sizeof(context->ImageName));

                count++;
            }
        }
    }

    *CountReturned = count;

    KeReleaseSpinLock(&g_ContextLock, oldIrql);
}

// ============================================================================
// ALLOWLIST CHECKING
// ============================================================================

/*++
Routine Description:
    Checks if a process image name matches any entry in the allowlist.
    Uses case-insensitive comparison because Windows file systems are
    case-insensitive by default.

    IRQL: This function only reads from the g_Allowlist array which
          is in the driver's non-paged .rdata section. Safe at any IRQL.
          However, the ProcessImageName buffer must be accessible at the
          caller's IRQL.

    Parameters:
        ProcessImageName - Full path or filename of the process image.
                           Can be NULL (returns FALSE).

Return Value:
    TRUE  - Process is allowlisted and should NOT be tracked/blocked.
    FALSE - Process is NOT allowlisted; should be tracked normally.
--*/
BOOLEAN
RsIsProcessAllowlisted(
    _In_ PUNICODE_STRING ProcessImageName
    )
{
    ULONG i;
    UNICODE_STRING processFileName;
    PWCHAR lastBackslash;

    if (ProcessImageName == NULL || ProcessImageName->Buffer == NULL ||
        ProcessImageName->Length == 0) {
        return FALSE;
    }

    //
    // Extract the filename portion from the full path.
    // The allowlist stores only filenames (e.g., "svchost.exe"), not
    // full paths (e.g., "C:\Windows\System32\svchost.exe").
    //
    // We find the last backslash and compare only what comes after it.
    // If no backslash is found, we compare the entire string.
    //
    lastBackslash = ProcessImageName->Buffer;
    for (i = 0; i < ProcessImageName->Length / sizeof(WCHAR); i++) {
        if (ProcessImageName->Buffer[i] == L'\\') {
            lastBackslash = &ProcessImageName->Buffer[i + 1];
        }
    }

    //
    // Build a UNICODE_STRING for just the filename portion.
    // We point into the original buffer (no allocation needed).
    //
    // Length = total bytes from filename start to end of original string.
    // This works because lastBackslash points into the original buffer.
    //
    processFileName.Buffer = lastBackslash;
    processFileName.Length = (USHORT)(
        (PUCHAR)ProcessImageName->Buffer + ProcessImageName->Length -
        (PUCHAR)lastBackslash
    );
    processFileName.MaximumLength = processFileName.Length;

    //
    // Check the static (built-in) allowlist.
    //
    for (i = 0; i < RS_ALLOWLIST_COUNT; i++) {
        if (RtlEqualUnicodeString(&processFileName, &g_Allowlist[i], TRUE)) {
            DbgPrint("RansomShield: PID allowlisted (static) - %wZ\n", &processFileName);
            return TRUE;
        }
    }

    //
    // Check the dynamic (user-pushed) allowlist under the spinlock.
    // Entries are non-paged globals so RtlEqualUnicodeString is safe at DISPATCH_LEVEL.
    //
    {
        KIRQL oldIrql;
        BOOLEAN found = FALSE;
        ULONG dynCount;

        KeAcquireSpinLock(&g_ContextLock, &oldIrql);
        dynCount = g_DynamicAllowlistCount;
        for (i = 0; i < dynCount; i++) {
            UNICODE_STRING dynEntry;
            RtlInitUnicodeString(&dynEntry, g_DynamicAllowlist[i]);
            if (RtlEqualUnicodeString(&processFileName, &dynEntry, TRUE)) {
                found = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_ContextLock, oldIrql);

        if (found) {
            DbgPrint("RansomShield: PID allowlisted (dynamic) - %wZ\n", &processFileName);
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// RUNTIME CONFIG AND DYNAMIC ALLOWLIST
// ============================================================================

VOID
RsApplyConfig(
    _In_ ULONG FileCountThreshold,
    _In_ ULONG TimeWindowSeconds,
    _In_ BOOLEAN MonitoringEnabled
    )
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ContextLock, &oldIrql);
    if (FileCountThreshold > 0) {
        g_FileCountThreshold = FileCountThreshold;
    }
    if (TimeWindowSeconds > 0) {
        g_TimeWindowSeconds = TimeWindowSeconds;
        g_TimeWindowTicks   = (LONGLONG)TimeWindowSeconds * 10000000LL;
    }
    g_MonitoringEnabled = MonitoringEnabled;
    KeReleaseSpinLock(&g_ContextLock, oldIrql);

    DbgPrint("RansomShield: RsApplyConfig: threshold=%lu window=%lu monitoring=%d\n",
             FileCountThreshold, TimeWindowSeconds, (int)MonitoringEnabled);
}

VOID
RsClearDynamicAllowlist(
    VOID
    )
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ContextLock, &oldIrql);
    g_DynamicAllowlistCount = 0;
    RtlZeroMemory(g_DynamicAllowlist, sizeof(g_DynamicAllowlist));
    KeReleaseSpinLock(&g_ContextLock, oldIrql);

    DbgPrint("RansomShield: Dynamic allowlist cleared\n");
}

VOID
RsAddDynamicAllowlistEntry(
    _In_reads_(EntryLen) PWCHAR Entry,
    _In_ ULONG EntryLen
    )
{
    KIRQL oldIrql;
    ULONG copyLen;

    if (Entry == NULL || EntryLen == 0) {
        return;
    }

    KeAcquireSpinLock(&g_ContextLock, &oldIrql);

    if (g_DynamicAllowlistCount < RS_MAX_ALLOWLIST_ENTRIES) {
        copyLen = EntryLen < (RS_MAX_ALLOWLIST_NAME_LEN - 1)
                  ? EntryLen
                  : (RS_MAX_ALLOWLIST_NAME_LEN - 1);

        RtlCopyMemory(g_DynamicAllowlist[g_DynamicAllowlistCount],
                      Entry,
                      copyLen * sizeof(WCHAR));
        g_DynamicAllowlist[g_DynamicAllowlistCount][copyLen] = L'\0';
        g_DynamicAllowlistCount++;
    }

    KeReleaseSpinLock(&g_ContextLock, oldIrql);
}

VOID
RsGetPidCounts(
    _Out_ PULONG TrackedCount,
    _Out_ PULONG BlockedCount
    )
{
    KIRQL oldIrql;
    ULONG blocked = 0;
    ULONG i;
    PLIST_ENTRY listHead, entry;
    PRS_PROCESS_CONTEXT context;

    KeAcquireSpinLock(&g_ContextLock, &oldIrql);

    for (i = 0; i < RS_HASH_TABLE_SIZE; i++) {
        listHead = &g_ContextHashTable[i];
        for (entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
            context = CONTAINING_RECORD(entry, RS_PROCESS_CONTEXT, Link);
            if (context->IsBlocked) {
                blocked++;
            }
        }
    }

    *TrackedCount = g_TrackedPidCount;
    *BlockedCount = blocked;

    KeReleaseSpinLock(&g_ContextLock, oldIrql);
}
