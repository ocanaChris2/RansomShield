/*++
Module Name:
    RansomShieldClient.h

Abstract:
    User-mode client header for communicating with the RansomShield
    minifilter driver. This file defines the shared protocol structures
    and provides a C/C++ interface wrapper for the Filter Manager API.

    USER-MODE CLIENT ARCHITECTURE:

    The user-mode service communicates with the kernel driver through
    the Filter Manager's communication port mechanism. The flow is:

    1. CONNECT: FilterConnectCommunicationPort() establishes a connection
       to the kernel driver's communication port.

    2. RECEIVE NOTIFICATIONS: A dedicated thread calls FilterGetMessage()
       in a loop to receive unsolicited notifications from the kernel
       (e.g., when a new PID is blocked).

    3. SEND QUERIES: The main thread calls FilterSendMessage() to send
       query requests (e.g., "give me the list of blocked PIDs") and
       receives a reply.

    4. DISCONNECT: Close the port handle to disconnect.

    USAGE EXAMPLE:

    ```cpp
    #include "RansomShieldClient.h"

    int main() {
        HANDLE hPort;
        HRESULT hr;

        // Step 1: Connect to the driver
        hr = RansomShieldConnect(&hPort);
        if (FAILED(hr)) {
            printf("Failed to connect: 0x%08X\n", hr);
            return 1;
        }

        // Step 2: Query blocked PIDs
        RS_REPLY_BLOCKED_PIDS reply;
        hr = RansomShieldQueryBlockedPids(hPort, &reply);
        if (SUCCEEDED(hr)) {
            for (ULONG i = 0; i < reply.Count; i++) {
                printf("Blocked PID: %lu (%ws)\n",
                       reply.Entries[i].ProcessId,
                       reply.Entries[i].ImageName);
            }
        }

        // Step 3: Unblock a PID (after admin confirmation)
        hr = RansomShieldUnblockPid(hPort, 1234);

        // Step 4: Disconnect
        RansomShieldDisconnect(hPort);
        return 0;
    }
    ```

    BUILD REQUIREMENTS:
    - Link with: fltLib.lib (Filter Manager user-mode library)
    - Include: fltUser.h, RansomShield.h (shared protocol header)
    - Target: Windows 10+ (for modern minifilter API support)

Author:
    RansomShield Development

Environment:
    User mode only
--*/

#ifndef _RANSOMSHIELD_CLIENT_H_
#define _RANSOMSHIELD_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

//
// The user-mode client needs the same protocol definitions as the kernel.
// In a real project, RansomShield.h would be a shared header included
// by both kernel and user mode. For this implementation, we reference
// the protocol structures defined in RansomShield.h.
//
// When building the user-mode client, include RansomShield.h AFTER
// defining _USER_MODE_ to exclude kernel-only declarations.
//
// IMPORTANT: The user-mode Filter Manager API adds its own headers
// (FILTER_MESSAGE_HEADER) before our data. We do NOT need to account
// for these headers in our structures — the Filter Manager handles
// them transparently.
//

#define _USER_MODE_
#include "RansomShield.h"
#undef _USER_MODE_

//
// Port name for user-mode connection.
// This must match RS_PORT_NAME in the kernel driver exactly, including
// the leading backslash. FilterConnectCommunicationPort() uses this
// name to find the kernel port object in the \Device\ namespace.
//
#define RS_CLIENT_PORT_NAME     L"\\RansomShieldPort"

//
// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================
//

/*++
Routine Description:
    Connects to the RansomShield minifilter driver's communication port.

    This function wraps FilterConnectCommunicationPort(). The connection
    is subject to the security descriptor on the port, which by default
    requires the caller to have SeLoadDriverPrivilege (administrator).

    Parameters:
        PortHandle - [out] Receives the connected port handle. The caller
                     must close this handle with RansomShieldDisconnect().

Return Value:
    S_OK            - Connected successfully.
    HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) - Caller is not an administrator.
    Other HRESULT   - Connection error.
--*/
static inline HRESULT
RansomShieldConnect(
    _Out_ HANDLE *PortHandle
    )
{
    return FilterConnectCommunicationPort(
        RS_CLIENT_PORT_NAME,
        0,                  // Options (reserved, must be 0)
        NULL,               // ConnectionContext (not used)
        0,                  // ContextSize
        NULL,               // SecurityAttributes (default)
        PortHandle
    );
}

/*++
Routine Description:
    Disconnects from the RansomShield driver's communication port.
    Simply closes the handle. The kernel driver will receive a
    disconnect notification callback.
--*/
static inline void
RansomShieldDisconnect(
    _In_ HANDLE PortHandle
    )
{
    if (PortHandle != NULL && PortHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(PortHandle);
    }
}

//
// ============================================================================
// QUERY INTERFACE
// ============================================================================
//

/*++
Routine Description:
    Queries the kernel driver for the list of currently blocked PIDs.

    This function sends an RsQueryBlockedPids message and waits for
    the kernel driver's reply.

    Parameters:
        PortHandle - Handle from RansomShieldConnect().
        Reply      - [out] Receives the list of blocked PIDs. The
                     Entries array within is fixed-size
                     (RS_MAX_REPORT_BLOCKED entries).

Return Value:
    S_OK         - Query succeeded.
    HRESULT      - Error code from FilterSendMessage or kernel driver.
--*/
static inline HRESULT
RansomShieldQueryBlockedPids(
    _In_ HANDLE PortHandle,
    _Out_ PRS_REPLY_BLOCKED_PIDS Reply
    )
{
    RS_REQUEST_BLOCKED_PIDS request;
    DWORD bytesReturned;

    //
    // Build the request.
    //
    RtlZeroMemory(&request, sizeof(request));
    request.Header.MessageType = RsQueryBlockedPids;
    request.Header.MessageSize = sizeof(RS_REQUEST_BLOCKED_PIDS);
    request.Header.SequenceNumber = 0;  // Kernel assigns sequence numbers

    //
    // Send the request and wait for the reply.
    // FilterSendMessage sends our buffer and receives the reply in one call.
    //
    return FilterSendMessage(
        PortHandle,
        &request,
        sizeof(request),
        Reply,
        sizeof(RS_REPLY_BLOCKED_PIDS),
        &bytesReturned
    );
}

/*++
Routine Description:
    Requests the kernel driver to unblock a specific PID.

    SECURITY: Only administrator processes can connect to the
    communication port, so this operation is restricted to admins.
    The kernel driver does not perform additional permission checks.

    Parameters:
        PortHandle - Handle from RansomShieldConnect().
        ProcessId  - The PID to unblock.

Return Value:
    S_OK         - PID was unblocked successfully.
    HRESULT      - Error code.
--*/
static inline HRESULT
RansomShieldUnblockPid(
    _In_ HANDLE PortHandle,
    _In_ ULONG ProcessId
    )
{
    RS_REQUEST_UNBLOCK_PID request;
    RS_REPLY_UNBLOCK_PID reply;
    DWORD bytesReturned;

    RtlZeroMemory(&request, sizeof(request));
    request.Header.MessageType = RsRequestUnblockPid;
    request.Header.MessageSize = sizeof(RS_REQUEST_UNBLOCK_PID);
    request.Header.SequenceNumber = 0;
    request.ProcessId = ProcessId;

    return FilterSendMessage(
        PortHandle,
        &request,
        sizeof(request),
        &reply,
        sizeof(reply),
        &bytesReturned
    );
}

//
// ============================================================================
// NOTIFICATION RECEIVER
// ============================================================================
//

/*++
Routine Description:
    Retrieves a pending notification from the kernel driver. This function
    should be called in a dedicated thread that loops continuously.

    The kernel driver pushes notifications when a new PID is blocked.
    These are unsolicited messages — the user-mode client does not need
    to send a request to receive them.

    TYPICAL NOTIFICATION THREAD PATTERN:
    ```cpp
    DWORD WINAPI NotificationThread(LPVOID param) {
        HANDLE hPort = (HANDLE)param;
        RS_NOTIFICATION_BLOCKED_PID notification;
        HRESULT hr;

        while (true) {
            hr = RansomShieldGetNotification(hPort, &notification);
            if (FAILED(hr)) {
                // Connection lost or driver unloaded
                break;
            }

            // Process the notification
            printf("ALERT: PID %lu blocked! Image: %ws\n",
                   notification.ProcessId,
                   notification.ImageName);

            // Show UI alert, log to SIEM, etc.
        }
        return 0;
    }
    ```

    Parameters:
        PortHandle    - Handle from RansomShieldConnect().
        Notification  - [out] Receives the notification data.

Return Value:
    S_OK         - Notification received successfully.
    HRESULT      - Error (e.g., driver disconnected).
--*/
static inline HRESULT
RansomShieldGetNotification(
    _In_ HANDLE PortHandle,
    _Out_ PRS_NOTIFICATION_BLOCKED_PID Notification
    )
{
    //
    // FilterGetMessage retrieves a message sent by the kernel via
    // FltSendMessage(). We must provide a buffer large enough for
    // the FILTER_MESSAGE_HEADER (prepended by the filter manager)
    // plus our notification data.
    //
    // The filter manager requires a FILTER_MESSAGE_HEADER at the
    // beginning of the buffer. It fills in this header with message
    // metadata before our notification data.
    //
    BYTE buffer[sizeof(FILTER_MESSAGE_HEADER) + sizeof(RS_NOTIFICATION_BLOCKED_PID)];

    HRESULT hr = FilterGetMessage(
        PortHandle,
        (PFILTER_MESSAGE_HEADER)buffer,
        sizeof(buffer),
        NULL                // Overlapped (not used for synchronous)
    );

    if (SUCCEEDED(hr)) {
        //
        // Copy the notification data (after the filter manager header).
        //
        RtlCopyMemory(Notification,
                      buffer + sizeof(FILTER_MESSAGE_HEADER),
                      sizeof(RS_NOTIFICATION_BLOCKED_PID));
    }

    return hr;
}

#ifdef __cplusplus
}
#endif

#endif /* _RANSOMSHIELD_CLIENT_H_ */
