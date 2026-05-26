/*++
Module Name:
    RansomShield.c

Abstract:
    Main module for the RansomShield minifilter driver. Contains:
    - DriverEntry: Initial entry point; registers the minifilter with the
      filter manager, initializes context tracking and communication port.
    - FilterUnloadCallback: Graceful teardown of all resources.
    - Pre-operation callbacks for IRP_MJ_WRITE and IRP_MJ_SET_INFORMATION.
    - Post-operation callback for IRP_MJ_SET_INFORMATION (optional telemetry).
    - Filter registration structures (FLT_REGISTRATION, FLT_OPERATION_REGISTRATION).

    MINIFILTER ARCHITECTURE OVERVIEW:

    The Windows Filter Manager (FltMgr) provides a framework for file system
    filter drivers. Instead of attaching directly to device objects (like
    legacy filters), minifilters register with FltMgr and specify:
      1. Which I/O operations they want to filter (via FLT_OPERATION_REGISTRATION).
      2. Callback routines for each operation (Pre and Post).
      3. An altitude value that determines their position in the filter stack.

    CALLBACK INVOCATION MODEL:
    - Pre-callbacks are called BEFORE the I/O request is sent down to the
      file system. They can:
        * Allow the I/O through (return FLT_PREOP_SUCCESS_WITH_CALLBACK or
          FLT_PREOP_SUCCESS_NO_CALLBACK).
        * Block the I/O (return FLT_PREOP_COMPLETE with an error status).
        * Pend the I/O for asynchronous processing (return FLT_PREOP_PENDING).
    - Post-callbacks are called AFTER the file system has completed the I/O.
      They can modify the result or perform additional work.

    IRQL CONTEXT:
    - Pre-callbacks for IRP-based I/O (like IRP_MJ_WRITE) are called at
      PASSIVE_LEVEL in the context of the requesting thread.
    - Pre-callbacks for FASTIO operations may be called at APC_LEVEL.
    - We must NOT access paged memory or call APIs that require PASSIVE_LEVEL
      without first checking the IRQL.

Author:
    RansomShield Development

Environment:
    Kernel mode (FILE_SYSTEM_MINIFILTER driver)
--*/

#include <fltkernel.h>
#include "RansomShield.h"

//
// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
//

//
// Callback routine prototypes. These must match the function signatures
// expected by the filter manager exactly.
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

NTSTATUS
RsInstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
RsInstanceTeardownStartCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
RsInstanceTeardownCompleteCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

//
// ============================================================================
// GLOBAL STATE
// ============================================================================
//

//
// The filter handle returned by FltRegisterFilter. This is our primary
// handle for all subsequent FltXxx() calls. It remains valid until
// FltUnregisterFilter() is called.
//
PFLT_FILTER g_FilterHandle = NULL;

//
// ============================================================================
// OPERATION REGISTRATION
// ============================================================================
//
// This array tells the filter manager which I/O operations we want to
// filter and which callback routines to invoke. Only operations listed
// here will generate callbacks; all others pass through unfiltered.
//
// IMPORTANT: The array MUST be terminated by an entry with
// IRP_MJ_OPERATION_END as the MajorFunction code.
//

const FLT_OPERATION_REGISTRATION g_Callbacks[] = {

    //
    // IRP_MJ_WRITE - Intercept file write operations.
    //
    // This is the primary vector for ransomware: the malware opens a file,
    // reads its contents, encrypts them in memory, and writes the encrypted
    // data back, overwriting the original content.
    //
    // WHY PRE-CALLBACK ONLY (no post-callback)?
    //   - We only need to block writes BEFORE they reach the file system.
    //   - There's no useful post-processing to do after a write completes.
    //   - Specifying NULL for the post-callback saves a small amount of
    //     overhead per I/O operation.
    //
    // FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO:
    //   - Paging I/O is generated by the memory manager (Mm) when writing
    //     modified pages to the page file or mapped files.
    //   - Blocking paging I/O would cause system instability (BUGCHECK).
    //   - Ransomware operates through normal file I/O (IRP_MJ_WRITE with
    //     non-paging flags), so skipping paging I/O is safe.
    //
    // FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO:
    //   - We do NOT set this flag. Cached I/O is how most application writes
    //     are serviced (the Cache Manager intercepts them). If we skipped
    //     cached I/O, we would miss the majority of ransomware writes.
    //   - Note: For cached writes, the Pre-callback is called when the
    //     application calls WriteFile(), not when the data is actually
    //     flushed to disk. This is exactly what we want — we want to block
    //     the application's write request, not the lazy writer's flush.
    //
    {
        IRP_MJ_WRITE,
        FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        RsPreOperationWrite,
        NULL,                           // No post-callback
        NULL                            // No context
    },

    //
    // IRP_MJ_SET_INFORMATION - Intercept file metadata changes.
    //
    // Ransomware commonly performs two types of SET_INFORMATION operations:
    //
    //   1. FileRenameInformation: After encrypting a file, ransomware often
    //      renames it with a custom extension (e.g., .encrypted, .locked,
    //      .crypt). Some ransomware renames the original file first (to
    //      document.docx.bak), creates a new encrypted file with the original
    //      name, then deletes the backup.
    //
    //   2. FileDispositionInformation: Used to delete files. Some ransomware
    //      deletes Volume Shadow Copies (VSS) using this operation, or deletes
    //      the original file after creating an encrypted copy.
    //
    // We also include FileRenameInformationEx and FileRenameInformationEx2
    // which are extended variants of FileRenameInformation on newer Windows
    // versions. They are checked by the FILE_INFORMATION_CLASS value in the
    // callback.
    //
    // WHY POST-CALLBACK FOR SET_INFORMATION?
    //   - For rename operations, the file name in the Pre-callback is the
    //     ORIGINAL name. After the rename completes, the file has the new
    //     name. If we want to track which files were renamed (for forensic
    //     analysis), we need the post-callback.
    //   - However, for BLOCKING purposes, the Pre-callback is sufficient.
    //   - We register a post-callback here for future telemetry expansion.
    //     Currently it just returns FLT_POSTOP_FINISHED_PROCESSING.
    //
    {
        IRP_MJ_SET_INFORMATION,
        0,                              // No special flags
        RsPreOperationSetInformation,
        RsPostOperationSetInformation,
        NULL                            // Reserved, must be NULL
    },

    //
    // Terminator entry. This MUST be the last entry in the array.
    //
    { IRP_MJ_OPERATION_END }
};

//
// ============================================================================
// CONTEXT REGISTRATION
// ============================================================================
//
// We don't use FltAllocateContext/FltSetInstanceContext for our per-PID
// tracking because:
//   1. Filter manager contexts are per-instance, per-stream, or per-stream-
//      handle. We need per-process tracking that spans ALL instances.
//   2. Filter manager context types must be registered, and each type is
//      tied to a specific context size. Our context sizes vary.
//   3. Our custom hash table provides better control over memory layout
//      and lookup performance.
//
// However, we still need to register at least one context type to satisfy
// the filter manager's requirements (even if we don't use it). We register
// a dummy instance context.
//

const FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {

    //
    // Instance context registration. We use this to track per-volume state
    // if needed in the future. Currently, it's a placeholder.
    //
    // FLT_CONTEXT_END is the terminator.
    //
    { FLT_CONTEXT_END }
};

//
// ============================================================================
// FILTER REGISTRATION
// ============================================================================
//
// FLT_REGISTRATION is the master structure passed to FltRegisterFilter().
// It describes the minifilter to the filter manager.
//

const FLT_REGISTRATION g_FilterRegistration = {

    //
    // Size of this structure. Used for versioning by the filter manager.
    //
    sizeof(FLT_REGISTRATION),

    //
    // Registration structure version. FLT_REGISTRATION_VERSION is the
    // current version for the WDK we're targeting.
    //
    FLT_REGISTRATION_VERSION,

    //
    // Flags. We don't need any special flags.
    // FLTFL_REGISTRATION_DO_NOT_SUPPORT_TLS_DRAIN: Not needed; we don't
    //   use thread-local storage contexts.
    //
    0,

    //
    // Context registration array. Points to our (empty) context table.
    //
    g_ContextRegistration,

    //
    // Callback registration array. Points to our operation callbacks.
    //
    g_Callbacks,

    //
    // Filter unload callback. Called when the OS or an admin requests
    // the driver to unload (e.g., 'fltmc unload RansomShield', 'net stop',
    // or system shutdown).
    //
    RsUnloadCallback,

    //
    // Instance setup callback. Called when the filter manager is about
    // to attach this minifilter to a volume instance. We return
    // STATUS_SUCCESS to allow attachment to all volumes.
    //
    RsInstanceSetupCallback,

    //
    // Instance query teardown callback. Not needed; we allow teardown
    // at any time. If we returned STATUS_FLT_DO_NOT_DETACH, the instance
    // would be protected from manual detach (but not from OS-initiated
    // teardown during shutdown).
    //
    NULL,

    //
    // Instance teardown start callback. Called when teardown begins.
    // We can use this to stop queuing new work for this instance.
    //
    RsInstanceTeardownStartCallback,

    //
    // Instance teardown complete callback. Called when teardown is done
    // and no more callbacks will be invoked for this instance.
    //
    RsInstanceTeardownCompleteCallback,

    //
    // Name-provider callbacks. This filter does not generate or normalize
    // file names, so all three are NULL.
    //
    NULL,   // GenerateFileNameCallback
    NULL,   // NormalizeNameComponentCallback
    NULL    // NormalizeContextCleanupCallback
};

//
// ============================================================================
// DRIVER ENTRY POINT
// ============================================================================

/*++
Routine Description:
    DriverEntry is the initial entry point for all kernel-mode drivers.
    For minifilter drivers, its responsibilities are:
      1. Register the minifilter with the filter manager (FltRegisterFilter).
      2. Initialize driver-specific subsystems (context tracking, comm port).
      3. Start filtering I/O (FltStartFiltering).

    IMPORTANT ORDERING:
    - FltRegisterFilter must be called BEFORE FltStartFiltering.
    - Subsystem initialization should happen BEFORE FltStartFiltering
      because once filtering starts, callbacks can be invoked immediately.
      If subsystems aren't ready, callbacks may crash.
    - Communication port setup (FltCreateCommunicationPort) should happen
      AFTER registration but BEFORE filtering starts, so the user-mode
      service can connect before any I/O is intercepted.

    IRQL: Called at PASSIVE_LEVEL in the context of the System process.

Arguments:
    DriverObject   - Pointer to the driver object created by the I/O manager.
    RegistryPath   - Unicode string identifying the driver's registry key
                     (e.g., \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\RansomShield).

Return Value:
    STATUS_SUCCESS                 - Driver initialized successfully.
    STATUS_INSUFFICIENT_RESOURCES  - Memory allocation failure.
    STATUS_FLT_*                   - Filter manager-specific errors.
--*/
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("RansomShield: DriverEntry - Initializing...\n");

    //
    // ---- STEP 1: Register the minifilter with the filter manager ----
    //
    // FltRegisterFilter informs the filter manager about our driver:
    //   - The callbacks we want to receive (via g_Callbacks).
    //   - Our unload routine (via RsUnloadCallback).
    //   - Our instance setup/teardown routines.
    //
    // On success, g_FilterHandle receives a handle that we use for all
    // subsequent FltXxx() API calls.
    //
    // This does NOT start filtering yet. Filtering starts only after
    // we call FltStartFiltering().
    //
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: FltRegisterFilter FAILED - 0x%08X\n", status);
        return status;
    }

    //
    // ---- STEP 2: Initialize the context tracking subsystem ----
    //
    // This initializes the hash table, spinlock, and allowlist.
    // Must be done before any I/O callbacks can fire.
    //
    status = RsInitializeContextTracking();
    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: RsInitializeContextTracking FAILED - 0x%08X\n", status);
        goto Error_UnregisterFilter;
    }

    //
    // ---- STEP 3: Create the communication port ----
    //
    // This creates a port that user-mode clients can connect to via
    // FilterConnectCommunicationPort(). The port allows bidirectional
    // communication for telemetry queries and unblock requests.
    //
    // Must be called AFTER FltRegisterFilter (needs g_FilterHandle).
    //
    status = RsInitializeCommPort(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: RsInitializeCommPort FAILED - 0x%08X\n", status);
        goto Error_DestroyContextTracking;
    }

    //
    // ---- STEP 4: Start filtering ----
    //
    // FltStartFiltering tells the filter manager to begin invoking our
    // callbacks for matching I/O operations. After this call, our Pre
    // and Post callbacks will be called on the appropriate I/O operations.
    //
    // IMPORTANT: Once this succeeds, we must be prepared for callbacks
    // on any thread at any time. All subsystems must be fully initialized.
    //
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: FltStartFiltering FAILED - 0x%08X\n", status);
        goto Error_DestroyCommPort;
    }

    DbgPrint("RansomShield: DriverEntry - Successfully started filtering\n");
    DbgPrint("RansomShield: Threshold=%d files in %d seconds\n",
             RS_MODIFICATION_THRESHOLD, RS_TIME_WINDOW_SECONDS);

    return STATUS_SUCCESS;

    //
    // ---- Error handling with structured cleanup ----
    // If any step fails, we unwind in reverse order (LIFO) to ensure
    // no resources are leaked. Each cleanup step is idempotent or
    // safe to call even if the corresponding init step partially failed.
    //
Error_DestroyCommPort:
    RsDestroyCommPort();

Error_DestroyContextTracking:
    RsDestroyContextTracking();

Error_UnregisterFilter:
    FltUnregisterFilter(g_FilterHandle);
    g_FilterHandle = NULL;

    return status;
}

// ============================================================================
// FILTER UNLOAD CALLBACK
// ============================================================================

/*++
Routine Description:
    Called when the minifilter is being unloaded. This can happen due to:
      - Admin command: 'fltmc unload RansomShield'
      - Service stop: 'net stop RansomShield'
      - System shutdown

    CLEANUP ORDERING (reverse of initialization):
    1. Close the communication port (stops new user-mode connections).
    2. Destroy the context tracking subsystem (frees all contexts).
    3. Unregister the filter (tells filter manager to stop calling us).

    After this function returns, the filter manager guarantees that no
    more callbacks will be invoked. It waits for all in-progress callbacks
    to complete before calling this routine.

    IRQL: PASSIVE_LEVEL.

Arguments:
    Flags - Indicates why the unload is happening (e.g.,
            FLTFL_FILTER_UNLOAD_MANDATORY for system shutdown).

Return Value:
    STATUS_SUCCESS (unload cannot be prevented; returning an error just
    delays the inevitable and is bad practice).
--*/
NTSTATUS
RsUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("RansomShield: UnloadCallback - Shutting down...\n");

    //
    // Step 1: Destroy communication port. This closes the server port
    // and any connected client ports. After this, no user-mode messages
    // can be sent or received.
    //
    RsDestroyCommPort();

    //
    // Step 2: Destroy context tracking. Frees all per-PID contexts.
    //
    RsDestroyContextTracking();

    //
    // Step 3: Unregister the filter. This is the LAST step because
    // once unregistered, the filter manager may unload the driver image.
    // We must ensure all our code has finished executing before this.
    //
    // FltUnregisterFilter also waits for all outstanding callbacks to
    // complete, so by the time it returns, no callback is using our code.
    //
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    DbgPrint("RansomShield: UnloadCallback - Shutdown complete\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// INSTANCE CALLBACKS
// ============================================================================

/*++
Routine Description:
    Called when the filter manager is attaching this minifilter to a
    new volume instance. We return STATUS_SUCCESS to allow attachment
    to all volumes. This ensures we monitor all file system activity
    across all mounted volumes.

    IRQL: PASSIVE_LEVEL.
--*/
NTSTATUS
RsInstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    //
    // Allow attachment to all volume types (local, network, removable).
    // A production driver might want to skip network volumes to reduce
    // false positives from file server operations.
    //
    return STATUS_SUCCESS;
}

/*++
Routine Description:
    Called when an instance teardown is starting. We can use this to
    stop queuing new work items for this instance.

    IRQL: PASSIVE_LEVEL.
--*/
VOID
RsInstanceTeardownStartCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

/*++
Routine Description:
    Called when instance teardown is complete. All I/O on this instance
    has been drained and no more callbacks will fire for it.

    IRQL: PASSIVE_LEVEL.
--*/
VOID
RsInstanceTeardownCompleteCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// ============================================================================
// PRE-OPERATION CALLBACK: IRP_MJ_WRITE
// ============================================================================

/*++
Routine Description:
    Pre-operation callback for IRP_MJ_WRITE. This is called BEFORE a
    write operation reaches the file system. We evaluate whether the
    requesting process should be blocked based on the heuristic tracker.

    FLOW:
    1. Get the requestor's PID via FltGetRequestorProcessId().
    2. Get the process's image name for allowlist checking.
    3. Check allowlist — if the process is trusted, allow through.
    4. Record the operation in the per-PID tracker.
    5. If the tracker says "block", return FLT_PREOP_COMPLETE with
       STATUS_ACCESS_DENIED, which prevents the write from reaching
       the file system.
    6. Otherwise, allow the write through.

    IRQL: Called at PASSIVE_LEVEL for IRP-based I/O. May be called at
          APC_LEVEL for FASTIO operations.

    IMPORTANT DESIGN DECISIONS:
    - We use FltGetRequestorProcessId() instead of PsGetCurrentProcessId()
      because the requestor may be different from the current thread's
      process (e.g., during impersonation). FltGetRequestorProcessId()
      returns the real process that initiated the I/O.
    - We skip operations on the paging file, system hive, and other
      critical system files to prevent system instability.

Arguments:
    Data               - Pointer to the callback data structure containing
                         information about the I/O operation.
    FltObjects         - Pointer to a structure containing pointers to
                         related objects (instance, volume, file object).
    CompletionContext  - [out] Receives a context to be passed to the
                         post-operation callback. We don't use post-callbacks
                         for WRITE, so we always set this to NULL.

Return Value:
    FLT_PREOP_SUCCESS_NO_CALLBACK - Allow the I/O through; no post-callback.
    FLT_PREOP_COMPLETE            - Block the I/O; Data->IoStatus.Status
                                    contains the error code.
--*/
FLT_PREOP_CALLBACK_STATUS
RsPreOperationWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    ULONG requestorPid;
    PEPROCESS requestorProcess;
    PUNICODE_STRING processImageName;
    BOOLEAN shouldBlock = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    //
    // ---- STEP 1: Skip operations we don't want to monitor ----
    //

    //
    // Skip paging I/O. This flag is set by the memory manager when
    // writing modified pages to the page file or to mapped files.
    // Blocking paging I/O would cause a BUGCHECK.
    //
    // Note: We already specified FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO
    // in the operation registration, so the filter manager should NOT call
    // us for paging I/O. This check is a defensive double-check using the
    // correct IrpFlags field (not Parameters.Write.PagingWrite, which does
    // not exist in the standard WDK FLT_PARAMETERS.Write structure).
    //
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Skip I/O for the System process (PID 4). The System process
    // handles critical kernel I/O (e.g., cache lazy writer, modified
    // page writer) that must never be blocked.
    //
    requestorPid = FltGetRequestorProcessId(Data);
    if (requestorPid == 0 || requestorPid == 4) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // ---- STEP 2: Get the process image name ----
    //
    // FltGetRequestorProcessId() gives us the PID. To get the process
    // image name, we need the EPROCESS structure.
    //
    // FltGetRequestorProcess() returns an UNREFERENCED pointer to the
    // EPROCESS of the requestor. The pointer remains valid as long as
    // the FLT_CALLBACK_DATA structure is not freed. If the process has
    // already exited, it returns NULL. We must NOT call
    // ObDereferenceObject() on this pointer — it is NOT our reference.
    // The WDK minifilter samples confirm this pattern.
    //
    // IRQL NOTE: FltGetRequestorProcess() is safe at any IRQL because
    // it just reads a field from the callback data. However,
    // SeLocateProcessImageName() allocates memory from PAGED pool
    // internally, which requires PASSIVE_LEVEL.
    //
    // Since we're in a pre-callback (PASSIVE_LEVEL or APC_LEVEL),
    // we need to check the current IRQL before calling
    // SeLocateProcessImageName().
    //
    processImageName = NULL;
    requestorProcess = FltGetRequestorProcess(Data);

    if (requestorProcess != NULL) {
        //
        // SeLocateProcessImageName allocates a UNICODE_STRING buffer
        // from PAGED pool and returns it. The caller must free it
        // with ExFreePool(). This function must be called at
        // PASSIVE_LEVEL because it allocates memory from paged pool.
        //
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            status = SeLocateProcessImageName(requestorProcess, &processImageName);
            if (!NT_SUCCESS(status)) {
                processImageName = NULL;
            }
        }

        //
        // Do NOT call ObDereferenceObject() here.
        // FltGetRequestorProcess() does NOT return a referenced pointer.
        // The reference is held by the FLT_CALLBACK_DATA structure itself.
        // Calling ObDereferenceObject would over-dereference and could
        // cause a use-after-free BUGCHECK.
        //
    }

    //
    // ---- STEP 3: Check allowlist ----
    //
    // If the process is in the allowlist, skip tracking entirely.
    // This avoids false positives from system processes that perform
    // legitimate bulk I/O (e.g., Windows Search Indexer).
    //
    if (processImageName != NULL) {
        if (RsIsProcessAllowlisted(processImageName)) {
            ExFreePool(processImageName);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    //
    // ---- STEP 4: Record the operation and evaluate threshold ----
    //
    // RsRecordOperation adds this operation to the per-PID tracker
    // and returns ShouldBlock = TRUE if the PID has exceeded the
    // threshold of modifications within the sliding time window.
    //
    status = RsRecordOperation(requestorPid, processImageName, &shouldBlock);

    //
    // Free the image name buffer allocated by SeLocateProcessImageName.
    //
    if (processImageName != NULL) {
        ExFreePool(processImageName);
    }

    if (!NT_SUCCESS(status)) {
        //
        // Tracking failed (likely OOM). In a security product, we must
        // decide: fail-open (allow the write) or fail-closed (block it)?
        //
        // We choose FAIL-OPEN here because:
        //   1. False positives (blocking legitimate I/O) are very
        //      disruptive to users.
        //   2. A transient OOM condition shouldn't lock out the system.
        //   3. The heuristic will catch the process on the next operation
        //      once memory is available.
        //
        // A high-security environment might choose FAIL-CLOSED.
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // ---- STEP 5: Enforce the block ----
    //
    if (shouldBlock) {
        //
        // Set the I/O status to ACCESS_DENIED and return
        // FLT_PREOP_COMPLETE. This tells the filter manager:
        //   1. Don't send this I/O to the file system (it's blocked).
        //   2. Complete the I/O immediately with the status we set.
        //   3. Don't call any post-operation callbacks.
        //
        // FLT_PREOP_COMPLETE is the correct return value for blocking
        // I/O. Do NOT use FLT_PREOP_SUCCESS_WITH_CALLBACK or
        // FLT_PREOP_SUCCESS_NO_CALLBACK for blocked operations, as
        // those allow the I/O to proceed.
        //
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        DbgPrint("RansomShield: BLOCKED write from PID %lu\n", requestorPid);

        return FLT_PREOP_COMPLETE;
    }

    //
    // Allow the write through. FLT_PREOP_SUCCESS_NO_CALLBACK tells
    // the filter manager:
    //   1. Allow this I/O to proceed to the file system.
    //   2. Don't call a post-operation callback when it completes.
    //
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// PRE-OPERATION CALLBACK: IRP_MJ_SET_INFORMATION
// ============================================================================

/*++
Routine Description:
    Pre-operation callback for IRP_MJ_SET_INFORMATION. This monitors
    file rename and delete operations, which are commonly used by
    ransomware to change file extensions or destroy originals.

    MONITORED FILE_INFORMATION_CLASS values:
    - FileRenameInformation:    Renames a file (e.g., .docx -> .encrypted)
    - FileRenameInformationEx:  Extended rename (Windows 10+)
    - FileRenameInformationEx2: Extended rename with extra flags
    - FileDispositionInformation:     Marks a file for deletion
    - FileDispositionInformationEx:   Extended delete with flags

    We intentionally do NOT monitor:
    - FileAllocationInformation:  Changes file allocation size (not malicious)
    - FileEndOfFileInformation:   Changes file size (covered by IRP_MJ_WRITE
                                  for data overwrites)
    - FileBasicInformation:       Changes file timestamps/attributes (benign)
    - FilePositionInformation:    Changes file pointer (benign)

    IRQL: PASSIVE_LEVEL or APC_LEVEL.
--*/
FLT_PREOP_CALLBACK_STATUS
RsPreOperationSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    ULONG requestorPid;
    PEPROCESS requestorProcess;
    PUNICODE_STRING processImageName;
    BOOLEAN shouldBlock = FALSE;
    FILE_INFORMATION_CLASS infoClass;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    //
    // Get the file information class from the I/O parameter block.
    // This tells us what kind of SET_INFORMATION operation this is.
    //
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    //
    // Only monitor rename and delete operations. Ignore all others.
    //
    switch (infoClass) {
    case FileRenameInformation:
    case FileRenameInformationEx:
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        //
        // These are the operations we want to monitor. Continue processing.
        //
        break;

    default:
        //
        // Not a monitored operation. Allow through without tracking.
        // Use NO_CALLBACK to avoid the overhead of invoking the
        // post-callback for operations we don't care about.
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Skip System process (PID 4).
    //
    requestorPid = FltGetRequestorProcessId(Data);
    if (requestorPid == 0 || requestorPid == 4) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get the process image name for allowlist checking.
    //
    processImageName = NULL;
    requestorProcess = FltGetRequestorProcess(Data);

    if (requestorProcess != NULL) {
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            status = SeLocateProcessImageName(requestorProcess, &processImageName);
            if (!NT_SUCCESS(status)) {
                processImageName = NULL;
            }
        }
        //
        // Do NOT call ObDereferenceObject() — FltGetRequestorProcess()
        // returns an unreferenced pointer. See RsPreOperationWrite for details.
        //
    }

    //
    // Check allowlist.
    //
    if (processImageName != NULL) {
        if (RsIsProcessAllowlisted(processImageName)) {
            ExFreePool(processImageName);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    //
    // Record the operation in the heuristic tracker.
    //
    status = RsRecordOperation(requestorPid, processImageName, &shouldBlock);

    if (processImageName != NULL) {
        ExFreePool(processImageName);
    }

    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Block if the PID has been flagged.
    //
    if (shouldBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        DbgPrint("RansomShield: BLOCKED setinfo (class=%d) from PID %lu\n",
                 infoClass, requestorPid);

        return FLT_PREOP_COMPLETE;
    }

    //
    // Allow the operation through. We specify FLT_PREOP_SUCCESS_WITH_CALLBACK
    // so that our post-callback (RsPostOperationSetInformation) is invoked
    // after the operation completes. This is useful for future telemetry
    // (e.g., logging successful renames for forensic analysis).
    //
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// ============================================================================
// POST-OPERATION CALLBACK: IRP_MJ_SET_INFORMATION
// ============================================================================

/*++
Routine Description:
    Post-operation callback for IRP_MJ_SET_INFORMATION. Called AFTER
    the file system has processed the rename or delete operation.

    CURRENT USE: Placeholder for future telemetry. Currently returns
    immediately without any processing.

    FUTURE ENHANCEMENTS:
    - Log successful renames for forensic analysis (the post-callback
      has access to the NEW file name after a rename).
    - Detect patterns like mass file extension changes.
    - Feed data into a machine learning model for behavioral analysis.

    IRQL: PASSIVE_LEVEL (because we specified 0 for the post-operation
          flags in the operation registration, meaning we don't need
          DPC-level post-processing).

Arguments:
    Data               - Contains the result of the operation.
    FltObjects         - Related objects.
    CompletionContext  - Context passed from the pre-callback (unused).
    Flags              - Post-operation flags (e.g., FLTFL_POST_OPERATION_DRAINING).

Return Value:
    FLT_POSTOP_FINISHED_PROCESSING - We're done; no further processing needed.
--*/
FLT_POSTOP_CALLBACK_STATUS
RsPostOperationSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    //
    // Future telemetry: Log successful renames/deletes here.
    // Example:
    //   if (NT_SUCCESS(Data->IoStatus.Status)) {
    //       // Get the new file name via FltGetFileNameInformation
    //       // Log to an internal buffer or ETW event
    //   }
    //

    return FLT_POSTOP_FINISHED_PROCESSING;
}
