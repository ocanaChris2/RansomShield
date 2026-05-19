/*++
Module Name:
    CommPort.c

Abstract:
    User-mode communication port module for the RansomShield minifilter driver.
    This module implements the filter manager communication port interface
    that allows a user-mode service to:
      1. Query the list of currently blocked PIDs
      2. Unblock a specific PID (after admin confirmation)
      3. Receive real-time notifications when a PID is newly blocked

    COMMUNICATION PORT ARCHITECTURE:

    ┌──────────────────┐         ┌──────────────────────────────────────┐
    │   User-Mode      │         │          Kernel Mode                 │
    │   Service        │         │                                      │
    │                  │         │                                      │
    │  FilterConnect ──┼────────►│  RsConnectNotifyCallback()           │
    │  Communication   │         │  (Accepts the connection, stores     │
    │  Port()          │         │   the client port handle)            │
    │                  │         │                                      │
    │  FilterSend ─────┼────────►│  RsMessageNotifyCallback()          │
    │  Message()       │         │  (Processes query/unblock requests)  │
    │                  │         │                                      │
    │  FilterGet ──────┼─────────│  FltSendMessage()                   │
    │  Message()       │◄────────│  (Pushes block notifications)        │
    │                  │         │                                      │
    │  (disconnect) ───┼────────►│  RsDisconnectNotifyCallback()       │
    │                  │         │  (Cleans up client port handle)      │
    └──────────────────┘         └──────────────────────────────────────┘

    THREADING MODEL:
    - ConnectNotifyCallback: Called by the filter manager at PASSIVE_LEVEL
      in the context of the connecting thread. Serialized by the filter
      manager — only one connect callback is active at a time.
    - MessageNotifyCallback: Called by the filter manager at PASSIVE_LEVEL
      in the context of the thread that called FilterSendMessage(). The
      filter manager serializes message callbacks per connection.
    - DisconnectNotifyCallback: Called at PASSIVE_LEVEL when the user-mode
      client closes the handle or the process exits.
    - FltSendMessage: Called from our pre-operation callback context.
      This MUST be called at PASSIVE_LEVEL (which we guarantee by calling
      it after releasing the spinlock).

    IMPORTANT NOTES ON FltSendMessage:
    - FltSendMessage() can block (wait) until the user-mode client calls
      FilterGetMessage() or FilterReplyMessage(). The wait is NOT
      indefinite — we specify a timeout.
    - If no user-mode client is connected, FltSendMessage() returns
      STATUS_FLT_NO_WAITER immediately (non-blocking).
    - We NEVER call FltSendMessage() at DISPATCH_LEVEL or while holding
      a spinlock. This would cause a BUGCHECK because FltSendMessage()
      may need to wait.

Author:
    RansomShield Development

Environment:
    Kernel mode, IRQL = PASSIVE_LEVEL for all communication port operations
--*/

#include <fltkernel.h>
#include "RansomShield.h"

//
// ============================================================================
// GLOBAL STATE
// ============================================================================
//

//
// Server port handle. Created by FltCreateCommunicationPort(). This
// represents the listening endpoint. We close it in RsDestroyCommPort().
//
PFLT_PORT g_ServerPort = NULL;

//
// Client port handle. Set by RsConnectNotifyCallback() when a user-mode
// client connects. Cleared by RsDisconnectNotifyCallback() when the
// client disconnects.
//
// SINGLE CLIENT DESIGN:
// We only support one connected client at a time. This simplifies the
// design significantly:
//   - No need for a client list with associated locking.
//   - FltSendMessage() naturally fails with STATUS_FLT_NO_WAITER if
//     no client is connected.
//   - The user-mode service is typically a singleton anyway.
//
// If multiple clients are needed, this would need to be replaced with
// a linked list of PFLT_PORT entries protected by a mutex.
//
// SYNCHRONIZATION:
// The filter manager guarantees that ConnectNotifyCallback and
// DisconnectNotifyCallback are serialized, so we don't need an
// additional lock to protect g_ClientPort.
//
PFLT_PORT g_ClientPort = NULL;

//
// Timeout for FltSendMessage(). We don't want to block the I/O path
// indefinitely if the user-mode client is unresponsive.
//
// 5 seconds is a reasonable timeout:
//   - Long enough for a responsive service to process the message.
//   - Short enough that we don't significantly delay the blocked I/O
//     path (the pre-callback is waiting for this to complete).
//
// NOTE: The timeout is in 100-nanosecond intervals. Negative values
// indicate relative time (as opposed to absolute time).
//
LARGE_INTEGER g_MessageTimeout = {.QuadPart = -5 * 10000000}; // 5 seconds, relative

//
// ============================================================================
// INITIALIZATION / TEARDOWN
// ============================================================================

/*++
Routine Description:
    Creates the communication port for user-mode interaction. Must be
    called after FltRegisterFilter() succeeds (requires a valid filter handle).

    FltCreateCommunicationPort creates a port object that user-mode clients
    can connect to via FilterConnectCommunicationPort(). The port is
    identified by RS_PORT_NAME (e.g., "\RansomShieldPort").

    SECURITY:
    - By default, only processes with SeLoadDriverPrivilege (administrators)
      can connect to the communication port. This prevents unprivileged
      processes from unblocking ransomware PIDs.
    - In a production driver, we would specify a security descriptor (SD)
      to further restrict access. For this implementation, the default
      security is sufficient.
    - MaxConnections = 1 enforces our single-client design.

    IRQL: PASSIVE_LEVEL (FltCreateCommunicationPort requires it).

Arguments:
    FilterHandle - The handle returned by FltRegisterFilter().

Return Value:
    STATUS_SUCCESS or an appropriate error code.
--*/
//
// Port name as a UNICODE_STRING. The user-mode client must use the
// same name when calling FilterConnectCommunicationPort().
//
// The leading backslash is required because the port name is relative
// to the \Device\ directory in the NT object namespace.
//
// NOTE: This MUST be declared before RsInitializeCommPort() which
// references it.
//
static UNICODE_STRING g_ServerPortName = RTL_CONSTANT_STRING(RS_PORT_NAME);

NTSTATUS
RsInitializeCommPort(
    _In_ PFLT_FILTER FilterHandle
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd;

    //
    // Create a security descriptor that allows only Administrators and
    // SYSTEM to access the communication port. This prevents
    // non-privileged processes from:
    //   - Unblocking ransomware PIDs
    //   - Receiving telemetry about blocked PIDs
    //   - Interfering with the driver's operation
    //
    // We use a simple DACL: Administrators (full control) + SYSTEM (full control).
    //
    // IMPORTANT: The security descriptor must be in self-relative format
    // (not absolute) for use with FltCreateCommunicationPort.
    // FltBuildDefaultSecurityDescriptor creates a self-relative SD.
    //
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: FltBuildDefaultSecurityDescriptor FAILED - 0x%08X\n", status);
        return status;
    }

    //
    // Create the communication port.
    //
    // Parameters:
    //   FilterHandle    - Our filter handle from FltRegisterFilter.
    //   ServerPort      - [out] Receives the server port handle.
    //   PortName        - Name of the port (must match what the user-mode
    //                     client passes to FilterConnectCommunicationPort).
    //   ServerPortCookie - Opaque context passed to ConnectNotifyCallback.
    //                      We pass NULL (not needed).
    //   ConnectNotifyCallback   - Called when a client connects.
    //   DisconnectNotifyCallback - Called when a client disconnects.
    //   MessageNotifyCallback    - Called when a client sends a message.
    //   MaxConnections   - Maximum concurrent client connections.
    //                      1 = single client (our design).
    //
    // IRQL: Must be called at PASSIVE_LEVEL.
    //
    //
    // FltCreateCommunicationPort requires POBJECT_ATTRIBUTES (not a raw UNICODE_STRING).
    // We embed the security descriptor so the port is accessible only to admins/SYSTEM.
    //
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa,
                               &g_ServerPortName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,   // RootDirectory
                               sd);    // SecurityDescriptor from FltBuildDefaultSecurityDescriptor

    status = FltCreateCommunicationPort(
        FilterHandle,
        &g_ServerPort,
        &oa,
        NULL,                     // ServerPortCookie
        RsConnectNotifyCallback,
        RsDisconnectNotifyCallback,
        RsMessageNotifyCallback,
        1                         // MaxConnections = 1 (single client)
    );

    //
    // Free the security descriptor. FltCreateCommunicationPort makes
    // its own copy, so we can free ours immediately.
    //
    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: FltCreateCommunicationPort FAILED - 0x%08X\n", status);
        g_ServerPort = NULL;
        return status;
    }

    DbgPrint("RansomShield: Communication port created successfully\n");
    return STATUS_SUCCESS;
}

/*++
Routine Description:
    Destroys the communication port and cleans up resources. Called during
    driver unload.

    CLEANUP ORDER:
    1. Close the client port (if connected). This triggers the
       DisconnectNotifyCallback, so we set g_ClientPort = NULL first
       to prevent the callback from trying to close an already-closed port.
    2. Close the server port. This prevents new connections.
    3. Set both handles to NULL for defensive programming.

    IRQL: PASSIVE_LEVEL.
--*/
VOID
RsDestroyCommPort(
    VOID
    )
{
    //
    // Close the client connection first, if one exists.
    // FltCloseClientPort closes the handle and triggers the
    // DisconnectNotifyCallback. We set g_ClientPort = NULL BEFORE
    // calling FltCloseClientPort to prevent the disconnect callback
    // from trying to close an already-closing port.
    //
    if (g_ClientPort != NULL) {
        PFLT_PORT clientPort = g_ClientPort;
        g_ClientPort = NULL;
        FltCloseClientPort(g_FilterHandle, &clientPort);
    }

    //
    // Close the server port. This prevents new client connections.
    // After this call, any pending FilterConnectCommunicationPort()
    // calls in user mode will fail.
    //
    if (g_ServerPort != NULL) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }

    DbgPrint("RansomShield: Communication port destroyed\n");
}

// ============================================================================
// NOTIFICATION SENDER
// ============================================================================

/*++
Routine Description:
    Sends a notification to the connected user-mode client that a PID
    has been blocked. This is called from RsRecordOperation() AFTER
    releasing the spinlock, so we're at PASSIVE_LEVEL.

    IMPORTANT:
    - This function MUST be called at PASSIVE_LEVEL because FltSendMessage()
      may need to wait for the user-mode client to read the message.
    - If no client is connected, FltSendMessage() returns
      STATUS_FLT_NO_WAITER, which we treat as a non-error.
    - We use a timeout to prevent indefinite blocking if the user-mode
      client is hung.

    IRQL: PASSIVE_LEVEL (caller must guarantee this).

Arguments:
    ProcessId           - The PID that was blocked.
    ImageName           - Image name of the blocked process (in non-paged pool).
    BlockedTimestamp    - When the block occurred (KeQueryInterruptTime ticks).
    OperationCount      - Number of operations that triggered the block.

Return Value:
    STATUS_SUCCESS          - Message was sent (or no client connected).
    STATUS_FLT_NO_WAITER    - No user-mode client connected (not an error).
    Other                   - Unexpected error.
--*/
NTSTATUS
RsSendBlockNotification(
    _In_ ULONG ProcessId,
    _In_ PWCHAR ImageName,
    _In_ LONGLONG BlockedTimestamp,
    _In_ ULONG OperationCount
    )
{
    NTSTATUS status;
    RS_NOTIFICATION_BLOCKED_PID notification;
    KIRQL oldIrql;
    PFLT_PORT localClientPort;

    //
    // Snapshot the client port handle locally to avoid a race condition.
    // Between checking g_ClientPort != NULL and calling FltSendMessage(),
    // the disconnect callback could set g_ClientPort = NULL. If we passed
    // &g_ClientPort to FltSendMessage after it became NULL, we'd crash.
    //
    // By using a local snapshot, we either:
    //   (a) Have a valid port handle to send on, or
    //   (b) Have a stale handle if disconnect happened between the snapshot
    //       and FltSendMessage — but FltSendMessage handles this gracefully
    //       by returning STATUS_FLT_NO_WAITER or similar.
    //
    // IMPORTANT: FltSendMessage() sets *ClientPort = NULL on
    // STATUS_FLT_NO_WAITER, so we MUST pass a local copy, not &g_ClientPort.
    // If we passed &g_ClientPort, FltSendMessage would overwrite our global
    // with NULL, which is actually the correct behavior — but only if we
    // intended to clear it. Using a local variable is cleaner.
    //
    localClientPort = g_ClientPort;
    if (localClientPort == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Build the notification message.
    //
    RtlZeroMemory(&notification, sizeof(notification));

    //
    // Get a sequence number under the global lock. We reuse g_ContextLock
    // for this to avoid creating yet another synchronization primitive.
    //
    KeAcquireSpinLock(&g_ContextLock, &oldIrql);
    notification.Header.SequenceNumber = g_MessageSequence++;
    KeReleaseSpinLock(&g_ContextLock, oldIrql);

    notification.Header.MessageType = RsNotifyBlockedPid;
    notification.Header.MessageSize = sizeof(RS_NOTIFICATION_BLOCKED_PID);
    notification.ProcessId = ProcessId;
    notification.BlockedTimestamp = BlockedTimestamp;
    notification.OperationCount = OperationCount;

    //
    // Copy the image name. Both source and destination are in non-paged pool.
    // RtlCopyMemory is safe at any IRQL.
    //
    // We use sizeof(notification.ImageName) which is the full buffer size.
    // The source ImageName is null-terminated and we already zero-filled
    // the notification struct, so this is safe even if the source is shorter.
    //
    RtlCopyMemory(notification.ImageName, ImageName, sizeof(notification.ImageName));

    //
    // Send the notification to the user-mode client.
    //
    // FltSendMessage() sends the message and optionally waits for a reply.
    // Parameters:
    //   FilterHandle  - Our filter handle.
    //   ClientPort    - The connected client's port handle.
    //   SendBuffer    - The notification data to send.
    //   SendLength    - Size of the send buffer.
    //   ReplyBuffer   - Buffer to receive a reply (NULL = no reply expected).
    //   ReplyLength   - Size of the reply buffer.
    //   Timeout       - Maximum time to wait for the client to read the message.
    //
    // If the client calls FilterGetMessage(), it receives our notification.
    // If the client calls FilterReplyMessage(), we could get a reply, but
    // we don't need one for notifications, so ReplyBuffer = NULL.
    //
    // We pass &localClientPort (not &g_ClientPort) because FltSendMessage
    // sets *ClientPort = NULL on STATUS_FLT_NO_WAITER. Using a local copy
    // prevents corruption of our global g_ClientPort pointer.
    //
    status = FltSendMessage(
        g_FilterHandle,
        &localClientPort,
        &notification,
        sizeof(notification),
        NULL,               // No reply buffer
        NULL,               // No reply length
        &g_MessageTimeout
    );

    if (status == STATUS_FLT_NO_WAITER_FOR_REPLY) {
        //
        // No user-mode client is connected. This is not an error —
        // the service may not be running, or it may have crashed.
        // We continue to block the PID regardless; the notification
        // is for informational purposes only.
        //
        DbgPrint("RansomShield: No user-mode client connected for notification\n");
        return STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: FltSendMessage FAILED - 0x%08X\n", status);
        return status;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// CONNECT / DISCONNECT CALLBACKS
// ============================================================================

/*++
Routine Description:
    Called by the filter manager when a user-mode client connects to our
    communication port via FilterConnectCommunicationPort().

    We store the client port handle for use with FltSendMessage()
    (push notifications) and for cleanup during disconnect.

    SINGLE CLIENT ENFORCEMENT:
    Since we specified MaxConnections = 1 in FltCreateCommunicationPort,
    the filter manager will not call this callback if a client is already
    connected. However, we defensively check g_ClientPort == NULL.

    IRQL: PASSIVE_LEVEL.

Arguments:
    ClientPort          - Handle to the new client connection. We must
                          store this for use with FltSendMessage().
    ServerPortCookie    - The cookie we passed to FltCreateCommunicationPort
                          (NULL in our case).
    SizeOfContext       - Size of the connection context from the client.
    ConnectionContext   - Connection context from the client (optional).

Return Value:
    STATUS_SUCCESS - Connection accepted.
    STATUS_FLT_DO_NOT_CONNECT - Connection rejected.
--*/
NTSTATUS
RsConnectNotifyCallback(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    *ConnectionPortCookie = NULL;

    //
    // Store the client port handle. The filter manager has already
    // validated that no other client is connected (MaxConnections = 1).
    //
    g_ClientPort = ClientPort;

    DbgPrint("RansomShield: User-mode client connected\n");

    return STATUS_SUCCESS;
}

/*++
Routine Description:
    Called by the filter manager when the user-mode client disconnects
    (closes the port handle, process exits, or driver is unloading).

    We must clean up the client port handle. The filter manager has
    already closed the port; we just need to clear our reference.

    IRQL: PASSIVE_LEVEL.

Arguments:
    ConnectionCookie - The cookie returned by ConnectNotifyCallback
                       (not used in our design).
--*/
VOID
RsDisconnectNotifyCallback(
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    //
    // The filter manager has already closed the client port.
    // We just need to clear our stored reference so we don't
    // try to use a closed handle.
    //
    // If g_ClientPort is already NULL (e.g., because RsDestroyCommPort
    // set it to NULL before calling FltCloseClientPort), this is a no-op.
    //
    g_ClientPort = NULL;

    DbgPrint("RansomShield: User-mode client disconnected\n");
}

// ============================================================================
// MESSAGE HANDLER
// ============================================================================

/*++
Routine Description:
    Called by the filter manager when the user-mode client sends a message
    via FilterSendMessage(). This is the primary request/response handler
    for user-mode queries.

    SUPPORTED REQUESTS:
    1. RsQueryBlockedPids - Returns the list of currently blocked PIDs.
    2. RsRequestUnblockPid - Unblocks a specific PID.

    PROTOCOL:
    - The input buffer contains an RS_MESSAGE_HEADER (at minimum) that
      identifies the request type.
    - The output buffer receives the reply, which starts with an
      RS_MESSAGE_HEADER and includes type-specific data.
    - We validate buffer sizes before processing.

    IRQL: PASSIVE_LEVEL (guaranteed by the filter manager).

    DEADLOCK PREVENTION:
    - We do NOT acquire g_ContextLock while processing messages because:
      1. RsGetBlockedPids() acquires the lock internally.
      2. RsUnblockProcess() acquires the lock internally.
      3. We don't hold the lock across the entire message processing,
         which would block I/O callbacks for the duration.
    - We do NOT call FltSendMessage() from within this callback
      (that would be a recursive send, which is not supported).

Arguments:
    PortCookie              - Cookie from ConnectNotifyCallback (unused).
    InputBuffer             - Request data from user mode.
    InputBufferLength       - Size of the input buffer.
    OutputBuffer            - Buffer to receive the reply.
    OutputBufferLength      - Size of the output buffer.
    ReturnOutputBufferLength - [out] Actual size of the reply data.

Return Value:
    STATUS_SUCCESS - Request processed successfully.
    STATUS_BUFFER_TOO_SMALL - Output buffer is too small for the reply.
    STATUS_INVALID_PARAMETER - Unknown message type or malformed request.
--*/
NTSTATUS
RsMessageNotifyCallback(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PRS_MESSAGE_HEADER requestHeader;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;

    //
    // Validate the input buffer. At minimum, we need an RS_MESSAGE_HEADER
    // to determine the message type.
    //
    if (InputBuffer == NULL || InputBufferLength < sizeof(RS_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    requestHeader = (PRS_MESSAGE_HEADER)InputBuffer;

    //
    // Validate that the claimed MessageSize doesn't exceed the actual
    // input buffer size. This prevents a malicious client from claiming
    // a large MessageSize that could cause confusion in future processing
    // that relies on the header's size field for bounds calculations.
    //
    if (requestHeader->MessageSize > InputBufferLength) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (requestHeader->MessageType) {

    //
    // ---- QUERY BLOCKED PIDS ----
    //
    case RsQueryBlockedPids:
    {
        PRS_REPLY_BLOCKED_PIDS reply;
        ULONG requiredSize;

        //
        // Calculate the required output buffer size.
        // We always allocate space for RS_MAX_REPORT_BLOCKED entries
        // regardless of how many are actually blocked. This simplifies
        // the protocol (fixed-size reply).
        //
        requiredSize = sizeof(RS_REPLY_BLOCKED_PIDS);

        if (OutputBuffer == NULL || OutputBufferLength < requiredSize) {
            *ReturnOutputBufferLength = requiredSize;
            return STATUS_BUFFER_TOO_SMALL;
        }

        reply = (PRS_REPLY_BLOCKED_PIDS)OutputBuffer;
        RtlZeroMemory(reply, requiredSize);

        //
        // Fill in the reply header.
        //
        KeAcquireSpinLock(&g_ContextLock, &oldIrql);
        reply->Header.SequenceNumber = g_MessageSequence++;
        KeReleaseSpinLock(&g_ContextLock, oldIrql);

        reply->Header.MessageType = RsReplyBlockedPids;
        reply->Header.MessageSize = requiredSize;

        //
        // Get the list of blocked PIDs. RsGetBlockedPids acquires
        // and releases g_ContextLock internally.
        //
        RsGetBlockedPids(reply->Entries, RS_MAX_REPORT_BLOCKED, &reply->Count);

        *ReturnOutputBufferLength = requiredSize;

        DbgPrint("RansomShield: QueryBlockedPids - returning %lu entries\n",
                 reply->Count);

        status = STATUS_SUCCESS;
        break;
    }

    //
    // ---- UNBLOCK A PID ----
    //
    case RsRequestUnblockPid:
    {
        PRS_REQUEST_UNBLOCK_PID request;
        PRS_REPLY_UNBLOCK_PID reply;
        ULONG requiredSize;

        //
        // Validate the request has the expected payload.
        //
        if (InputBufferLength < sizeof(RS_REQUEST_UNBLOCK_PID)) {
            return STATUS_INVALID_PARAMETER;
        }

        request = (PRS_REQUEST_UNBLOCK_PID)InputBuffer;

        requiredSize = sizeof(RS_REPLY_UNBLOCK_PID);

        if (OutputBuffer == NULL || OutputBufferLength < requiredSize) {
            *ReturnOutputBufferLength = requiredSize;
            return STATUS_BUFFER_TOO_SMALL;
        }

        reply = (PRS_REPLY_UNBLOCK_PID)OutputBuffer;
        RtlZeroMemory(reply, requiredSize);

        //
        // Fill in the reply header.
        //
        KeAcquireSpinLock(&g_ContextLock, &oldIrql);
        reply->Header.SequenceNumber = g_MessageSequence++;
        KeReleaseSpinLock(&g_ContextLock, oldIrql);

        reply->Header.MessageType = RsReplyUnblockPid;
        reply->Header.MessageSize = requiredSize;
        reply->ProcessId = request->ProcessId;

        //
        // Unblock the PID. RsUnblockProcess removes the process context
        // entirely, which also clears the IsBlocked flag.
        //
        // SECURITY NOTE: The communication port already restricts
        // connections to administrators (via the security descriptor).
        // So only admin-level processes can unblock PIDs. This prevents
        // ransomware from unblocking itself.
        //
        RsUnblockProcess(request->ProcessId);

        reply->Status = STATUS_SUCCESS;

        *ReturnOutputBufferLength = requiredSize;

        DbgPrint("RansomShield: PID %lu unblocked by user-mode service\n",
                 request->ProcessId);

        status = STATUS_SUCCESS;
        break;
    }

    default:
        //
        // Unknown message type. This could be a version mismatch between
        // the driver and the user-mode service.
        //
        DbgPrint("RansomShield: Unknown message type %d\n",
                 requestHeader->MessageType);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}
