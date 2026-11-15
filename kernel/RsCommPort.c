/*++
Module Name:
    RsCommPort.c

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
    │                  │         │  (Closes the client port)            │
    └──────────────────┘         └──────────────────────────────────────┘

    THREADING MODEL:
    - ConnectNotifyCallback: Called by the filter manager at PASSIVE_LEVEL
      in the context of the connecting thread. Serialized by the filter
      manager — only one connect callback is active at a time.
    - MessageNotifyCallback: Called by the filter manager at PASSIVE_LEVEL
      in the context of the thread that called FilterSendMessage(). Its
      input and output buffers are raw user-mode buffers: each is copied
      exactly once (in, then out) inside __try/__except, and never touched
      while a lock is held.
    - DisconnectNotifyCallback: Called at PASSIVE_LEVEL when the user-mode
      client closes the handle or the process exits, and from
      FltUnregisterFilter for a client still connected at unload. It must
      close the client port with FltCloseClientPort().
    - FltSendMessage: Called from our pre-operation callback context.
      It must not be called with a spinlock held (we call it after
      releasing g_ContextLock).

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
// client connects. Closed and cleared by RsDisconnectNotifyCallback()
// (FltCloseClientPort sets it to NULL).
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
// Connect and disconnect callbacks are serialized by the filter manager.
// The disconnect callback closes the port with FltCloseClientPort(), which
// sets g_ClientPort to NULL, and RsSendBlockNotification passes
// &g_ClientPort itself (never a copy) to FltSendMessage(). This is the
// pattern of the WDK scanner sample.
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
// Largest request the protocol defines. Larger input is rejected before
// anything is allocated, so a client cannot make the driver allocate
// arbitrary amounts of non-paged pool.
//
#define RS_MAX_REQUEST_SIZE     sizeof(RS_REQUEST_UPDATE_ALLOWLIST_FULL)

C_ASSERT(sizeof(RS_REQUEST_UPDATE_ALLOWLIST_CHUNK) <= RS_MAX_REQUEST_SIZE);
C_ASSERT(sizeof(RS_REQUEST_UPDATE_CONFIG)          <= RS_MAX_REQUEST_SIZE);
C_ASSERT(sizeof(RS_REQUEST_UNBLOCK_PID)            <= RS_MAX_REQUEST_SIZE);

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
    Closes the server port so no new client can connect. Called from
    RsTeardown (driver unload, or a failed DriverEntry) BEFORE
    FltUnregisterFilter.

    The client port is deliberately NOT closed here. A client that is still
    connected is disconnected by FltUnregisterFilter, which calls
    RsDisconnectNotifyCallback, and that callback closes the client port
    (the WDK scanner sample does the same). Closing it here as well would
    race with that callback.

    Safe to call when the server port was never created.

    IRQL: PASSIVE_LEVEL.
--*/
VOID
RsDestroyCommPort(
    VOID
    )
{
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
    releasing the spinlock.

    IMPORTANT:
    - This function must not be called with a spinlock held because
      FltSendMessage() may need to wait for the user-mode client to read
      the message.
    - If no client is connected, there is nothing to send; the block is
      already in force regardless.
    - We use a timeout to prevent indefinite blocking if the user-mode
      client is hung.

    IRQL: <= APC_LEVEL, no spinlock held.

Arguments:
    ProcessId           - The PID that was blocked.
    ImageName           - Image name of the blocked process (in non-paged pool).
    BlockedTimestamp    - When the block occurred (KeQueryInterruptTime ticks).
    OperationCount      - Number of operations that triggered the block.

Return Value:
    STATUS_SUCCESS          - Message was sent (or no client connected).
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

    //
    // Fast path: no client connected. A client that disconnects after this
    // check is handled by FltSendMessage (see below).
    //
    if (g_ClientPort == NULL) {
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

    notification.Header.MessageType     = RsNotifyBlockedPid;
    notification.Header.MessageSize     = sizeof(RS_NOTIFICATION_BLOCKED_PID);
    notification.Header.ProtocolVersion = RS_PROTOCOL_VERSION;
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
    //   ClientPort    - Address of the variable holding the client port.
    //   SendBuffer    - The notification data to send.
    //   SendLength    - Size of the send buffer.
    //   ReplyBuffer   - Buffer to receive a reply (NULL = no reply expected).
    //   ReplyLength   - Size of the reply buffer.
    //   Timeout       - Maximum time to wait for the client to read the message.
    //
    // We pass &g_ClientPort itself, not a local copy, as the WDK scanner
    // sample does. RsDisconnectNotifyCallback closes the port with
    // FltCloseClientPort(..., &g_ClientPort), which clears this variable; a
    // copy taken earlier could still point at a port that has been closed.
    //
    status = FltSendMessage(
        g_FilterHandle,
        &g_ClientPort,
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
    (closes the port handle or exits), and from FltUnregisterFilter for a
    client still connected when the driver unloads.

    The minifilter owns the client port and must close it here; the filter
    manager does not. Leaving it open would leak the port and, with
    MaxConnections = 1, can keep the next client from connecting.
    FltCloseClientPort also sets g_ClientPort to NULL.

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

    FltCloseClientPort(g_FilterHandle, &g_ClientPort);

    DbgPrint("RansomShield: User-mode client disconnected\n");
}

// ============================================================================
// MESSAGE HANDLER
// ============================================================================

/*++
Routine Description:
    Returns the reply size for a user -> kernel request type. (Request
    payload sizes are checked inline in each handler case, right where the
    payload is read.)

Return Value:
    STATUS_SUCCESS, or STATUS_INVALID_PARAMETER for a type that is not a
    user -> kernel request.
--*/
static
NTSTATUS
RsGetReplySize(
    _In_ RS_MESSAGE_TYPE MessageType,
    _Out_ PULONG ReplySize
    )
{
    switch (MessageType) {

    case RsQueryBlockedPids:
        *ReplySize = (ULONG)sizeof(RS_REPLY_BLOCKED_PIDS);
        break;

    case RsRequestUnblockPid:
        *ReplySize = (ULONG)sizeof(RS_REPLY_UNBLOCK_PID);
        break;

    case RsQueryConfig:
        *ReplySize = (ULONG)sizeof(RS_REPLY_CONFIG);
        break;

    case RsQueryAllowlist:
        *ReplySize = (ULONG)sizeof(RS_REPLY_ALLOWLIST);
        break;

    case RsRequestPause:
    case RsRequestResume:
    case RsUpdateConfig:
    case RsClearAllowlist:
    case RsUpdateAllowlistChunk:
    case RsUpdateAllowlistFull:
        *ReplySize = (ULONG)sizeof(RS_REPLY_GENERIC);
        break;

    default:
        *ReplySize = 0;
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/*++
Routine Description:
    Exception filter for the copies to and from the client's raw user-mode
    buffers. Handles only the faults a bad or vanishing user buffer can
    raise: an invalid or unmapped address, a misaligned access, a paging
    error on a mapped view. Any other exception is a driver bug and is not
    swallowed (which is also what Code Analysis rule C6320 asks for).
--*/
static
LONG
RsUserBufferExceptionFilter(
    _In_ NTSTATUS ExceptionCode
    )
{
    switch (ExceptionCode) {
    case STATUS_ACCESS_VIOLATION:
    case STATUS_DATATYPE_MISALIGNMENT:
    case STATUS_IN_PAGE_ERROR:
        return EXCEPTION_EXECUTE_HANDLER;
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

/*++
Routine Description:
    Fills a reply header. Header points into the non-paged kernel reply
    buffer, so writing it while holding g_ContextLock is legal.
--*/
static
VOID
RsFillReplyHeader(
    _Out_ PRS_MESSAGE_HEADER Header,
    _In_ RS_MESSAGE_TYPE MessageType,
    _In_ ULONG MessageSize
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_ContextLock, &oldIrql);
    Header->SequenceNumber = g_MessageSequence++;
    KeReleaseSpinLock(&g_ContextLock, oldIrql);

    Header->MessageType     = MessageType;
    Header->MessageSize     = MessageSize;
    Header->ProtocolVersion = RS_PROTOCOL_VERSION;
}

/*++
Routine Description:
    Called by the filter manager when the user-mode client sends a message
    via FilterSendMessage(). This is the request/response handler for all
    user-mode queries, commands and configuration updates.

    BUFFER HANDLING:
    InputBuffer and OutputBuffer are raw user-mode buffers: pageable, and
    another thread in the client can change or unmap them at any moment.
    Therefore:
      1. The request is copied ONCE into a non-paged kernel buffer, inside
         __try/__except, and only that copy is read afterwards. A field
         such as EntryCount cannot change between its check and its use.
      2. The reply is built in a non-paged kernel buffer. Some handlers
         fill it while holding g_ContextLock (DISPATCH_LEVEL), where
         touching pageable memory, which includes any user buffer, is a
         bugcheck.
      3. The reply is copied out to OutputBuffer at the end, inside
         __try/__except, with no lock held.
    Requests larger than RS_MAX_REQUEST_SIZE are rejected before anything
    is allocated.

    DEADLOCK PREVENTION:
    - No lock is held across the whole message. Each helper
      (RsGetBlockedPids, RsUnblockProcess, RsApplyConfig, the allowlist
      routines) takes and releases its own lock.
    - We do NOT call FltSendMessage() from within this callback
      (that would be a recursive send, which is not supported).

    IRQL: PASSIVE_LEVEL (guaranteed by the filter manager).

Arguments:
    PortCookie              - Cookie from ConnectNotifyCallback (unused).
    InputBuffer             - Request data from user mode.
    InputBufferLength       - Size of the input buffer.
    OutputBuffer            - Buffer to receive the reply.
    OutputBufferLength      - Size of the output buffer.
    ReturnOutputBufferLength - [out] Actual size of the reply data.

Return Value:
    STATUS_SUCCESS                - Request processed successfully.
    STATUS_BUFFER_TOO_SMALL       - Output buffer is too small for the reply;
                                    *ReturnOutputBufferLength = size needed.
    STATUS_INVALID_PARAMETER      - Unknown message type, malformed request,
                                    or an out-of-range configuration value.
    STATUS_INSUFFICIENT_RESOURCES - The kernel copies could not be allocated.
    Exception code                - A client buffer was invalid while copying.
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
    PUCHAR request = NULL;          // kernel copy of InputBuffer
    PUCHAR reply = NULL;            // kernel reply, copied to OutputBuffer at the end
    PRS_MESSAGE_HEADER requestHeader;
    RS_MESSAGE_TYPE messageType;
    ULONG replySize = 0;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(PortCookie);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL ||
        InputBufferLength < sizeof(RS_MESSAGE_HEADER) ||
        InputBufferLength > RS_MAX_REQUEST_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // ---- 1. Capture the request ----
    //
    request = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, InputBufferLength, RS_POOL_TAG);
    if (request == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Filter Manager has already probed InputBuffer for read and OutputBuffer
    // for write before calling this routine (see the WDK minispy sample), so
    // they are not probed again here. They are still raw user-mode buffers
    // that can become invalid at any time, so every access to them stays
    // inside __try/__except.
    //
    __try {
        RtlCopyMemory(request, InputBuffer, InputBufferLength);
    } __except (RsUserBufferExceptionFilter(GetExceptionCode())) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    //
    // From here on only the kernel copy is read.
    //
    requestHeader = (PRS_MESSAGE_HEADER)request;
    messageType = requestHeader->MessageType;

    //
    // Validate that the claimed MessageSize doesn't exceed the actual
    // input size. This prevents a client from claiming a large
    // MessageSize that later processing might rely on for bounds.
    //
    if (requestHeader->MessageSize > InputBufferLength) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    status = RsGetReplySize(messageType, &replySize);
    if (!NT_SUCCESS(status)) {
        DbgPrint("RansomShield: Unknown message type %d\n", (int)messageType);
        goto Exit;
    }

    if (OutputBuffer == NULL || OutputBufferLength < replySize) {
        *ReturnOutputBufferLength = replySize;
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    //
    // ---- 2. Build the reply in kernel memory ----
    //
    // Non-paged because some handlers fill it while holding g_ContextLock;
    // zero-filled by ExAllocatePool2, so unused fields and slots are 0.
    //
    reply = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, replySize, RS_POOL_TAG);
    if (reply == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Header-only requests need nothing beyond the header checked above.
    // Requests with a payload check their own size right before the payload
    // is read.
    //
    switch (messageType) {

    //
    // ---- QUERY BLOCKED PIDS ----
    //
    case RsQueryBlockedPids:
    {
        PRS_REPLY_BLOCKED_PIDS r = (PRS_REPLY_BLOCKED_PIDS)reply;

        RsFillReplyHeader(&r->Header, RsReplyBlockedPids, replySize);

        //
        // Fixed-size reply with room for RS_MAX_REPORT_BLOCKED entries.
        // RsGetBlockedPids fills it under g_ContextLock, which is why the
        // reply must be non-paged kernel memory.
        //
        RsGetBlockedPids(r->Entries, RS_MAX_REPORT_BLOCKED, &r->Count);

        DbgPrint("RansomShield: QueryBlockedPids - returning %lu entries\n", r->Count);
        break;
    }

    //
    // ---- UNBLOCK A PID ----
    //
    case RsRequestUnblockPid:
    {
        PRS_REQUEST_UNBLOCK_PID q = (PRS_REQUEST_UNBLOCK_PID)request;
        PRS_REPLY_UNBLOCK_PID r = (PRS_REPLY_UNBLOCK_PID)reply;

        if (InputBufferLength < sizeof(RS_REQUEST_UNBLOCK_PID)) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        //
        // SECURITY NOTE: The communication port already restricts
        // connections to administrators (via the security descriptor).
        // So only admin-level processes can unblock PIDs. This prevents
        // ransomware from unblocking itself.
        //
        // RsUnblockProcess removes the process context entirely, which
        // also clears the IsBlocked flag.
        //
        RsUnblockProcess(q->ProcessId);

        RsFillReplyHeader(&r->Header, RsReplyUnblockPid, replySize);
        r->ProcessId = q->ProcessId;
        r->Status = STATUS_SUCCESS;

        DbgPrint("RansomShield: PID %lu unblocked by user-mode service\n", q->ProcessId);
        break;
    }

    //
    // ---- QUERY CURRENT CONFIG ----
    //
    case RsQueryConfig:
    {
        PRS_REPLY_CONFIG r = (PRS_REPLY_CONFIG)reply;

        RsFillReplyHeader(&r->Header, RsQueryConfig, replySize);

        KeAcquireSpinLock(&g_ContextLock, &oldIrql);
        r->FileCountThreshold = g_FileCountThreshold;
        r->TimeWindowSeconds  = g_TimeWindowSeconds;
        r->MonitoringEnabled  = g_MonitoringEnabled;
        KeReleaseSpinLock(&g_ContextLock, oldIrql);

        RsGetPidCounts(&r->TrackedPidCount, &r->BlockedPidCount);
        break;
    }

    //
    // ---- QUERY CURRENT ALLOWLIST ----
    //
    case RsQueryAllowlist:
    {
        PRS_REPLY_ALLOWLIST r = (PRS_REPLY_ALLOWLIST)reply;

        RsFillReplyHeader(&r->Header, RsQueryAllowlist, replySize);
        RsSnapshotDynamicAllowlist(r->Entries, RS_MAX_ALLOWLIST_ENTRIES, &r->Count);
        break;
    }

    //
    // ---- PAUSE / RESUME MONITORING ----
    //
    case RsRequestPause:
    case RsRequestResume:
    {
        PRS_REPLY_GENERIC r = (PRS_REPLY_GENERIC)reply;
        BOOLEAN enable = (messageType == RsRequestResume) ? TRUE : FALSE;

        KeAcquireSpinLock(&g_ContextLock, &oldIrql);
        g_MonitoringEnabled = enable;
        KeReleaseSpinLock(&g_ContextLock, oldIrql);

        RsFillReplyHeader(&r->Header, messageType, replySize);
        r->Status = STATUS_SUCCESS;

        if (enable) {
            DbgPrint("RansomShield: Monitoring resumed\n");
        } else {
            DbgPrint("RansomShield: Monitoring paused\n");
        }
        break;
    }

    //
    // ---- UPDATE CONFIG ----
    //
    case RsUpdateConfig:
    {
        PRS_REQUEST_UPDATE_CONFIG q = (PRS_REQUEST_UPDATE_CONFIG)request;
        PRS_REPLY_GENERIC r = (PRS_REPLY_GENERIC)reply;

        if (InputBufferLength < sizeof(RS_REQUEST_UPDATE_CONFIG)) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        //
        // RsApplyConfig rejects out-of-range values without changing
        // anything; the failure is returned to the client.
        //
        status = RsApplyConfig(q->FileCountThreshold,
                               q->TimeWindowSeconds,
                               q->MonitoringEnabled);
        if (!NT_SUCCESS(status)) {
            DbgPrint("RansomShield: UpdateConfig rejected (threshold=%lu, window=%lu)\n",
                     q->FileCountThreshold, q->TimeWindowSeconds);
            goto Exit;
        }

        RsFillReplyHeader(&r->Header, RsUpdateConfig, replySize);
        r->Status = STATUS_SUCCESS;
        break;
    }

    //
    // ---- CLEAR ALLOWLIST ----
    //
    case RsClearAllowlist:
    {
        PRS_REPLY_GENERIC r = (PRS_REPLY_GENERIC)reply;

        RsClearDynamicAllowlist();

        RsFillReplyHeader(&r->Header, RsClearAllowlist, replySize);
        r->Status = STATUS_SUCCESS;
        break;
    }

    //
    // ---- UPDATE ALLOWLIST (CHUNK): append ----
    //
    case RsUpdateAllowlistChunk:
    {
        PRS_REQUEST_UPDATE_ALLOWLIST_CHUNK q = (PRS_REQUEST_UPDATE_ALLOWLIST_CHUNK)request;
        PRS_REPLY_GENERIC r = (PRS_REPLY_GENERIC)reply;

        //
        // q is the kernel copy, so EntryCount cannot change between this
        // check and its use.
        //
        if (InputBufferLength < sizeof(RS_REQUEST_UPDATE_ALLOWLIST_CHUNK) ||
            q->EntryCount > RS_MAX_ALLOWLIST_CHUNK) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        RsUpdateDynamicAllowlist(q->Entries, q->EntryCount, FALSE);

        RsFillReplyHeader(&r->Header, RsUpdateAllowlistChunk, replySize);
        r->Status = STATUS_SUCCESS;
        break;
    }

    //
    // ---- UPDATE ALLOWLIST (FULL): replace ----
    //
    case RsUpdateAllowlistFull:
    {
        PRS_REQUEST_UPDATE_ALLOWLIST_FULL q = (PRS_REQUEST_UPDATE_ALLOWLIST_FULL)request;
        PRS_REPLY_GENERIC r = (PRS_REPLY_GENERIC)reply;

        if (InputBufferLength < sizeof(RS_REQUEST_UPDATE_ALLOWLIST_FULL) ||
            q->EntryCount > RS_MAX_ALLOWLIST_ENTRIES) {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        RsUpdateDynamicAllowlist(q->Entries, q->EntryCount, TRUE);

        RsFillReplyHeader(&r->Header, RsUpdateAllowlistFull, replySize);
        r->Status = STATUS_SUCCESS;
        break;
    }

    default:
        //
        // RsGetReplySize already rejected every other type.
        //
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // ---- 3. Copy the reply out to the client ----
    //
    __try {
        RtlCopyMemory(OutputBuffer, reply, replySize);   // probed by Filter Manager (see step 1)
        *ReturnOutputBufferLength = replySize;
    } __except (RsUserBufferExceptionFilter(GetExceptionCode())) {
        status = GetExceptionCode();
    }

Exit:
    if (reply != NULL) {
        ExFreePoolWithTag(reply, RS_POOL_TAG);
    }

    ExFreePoolWithTag(request, RS_POOL_TAG);

    return status;
}
