/*++
Module Name:
    CommManager.cpp

Abstract:
    Implementation of the Communication Manager. See CommManager.h for
    architecture overview and design rationale.

    FILTER MANAGER USER-MODE API OVERVIEW:

    The Filter Manager provides three user-mode functions for communication:

    1. FilterConnectCommunicationPort()
       - Establishes a connection to a minifilter's communication port.
       - Returns a handle that can be used with FilterGetMessage and
         FilterSendMessage.
       - The port name must match the name passed to
         FltCreateCommunicationPort() in the kernel driver.
       - Requires SeLoadDriverPrivilege (Administrator or SYSTEM).
       - SYNCHRONOUS: Blocks until the connection is established or fails.

    2. FilterGetMessage()
       - Retrieves a message sent by the kernel via FltSendMessage().
       - BLOCKING: Waits until a message is available or the port is closed.
       - The buffer must start with a FILTER_MESSAGE_HEADER which the
         filter manager fills in with metadata. The application data
         follows immediately after the header.
       - Can be used with overlapped I/O for non-blocking operation.
       - When the port is closed (driver unload, disconnect), returns
         an error that should terminate the listener loop.

    3. FilterSendMessage()
       - Sends a request to the kernel and optionally receives a reply.
       - The kernel's MessageNotifyCallback processes the request and
         writes the reply into the output buffer.
       - SEMI-BLOCKING: Blocks until the kernel callback returns, but
         has a timeout (not directly configurable from user mode; the
         kernel controls the wait via FltSendMessage's timeout).
       - Not the same as FilterReplyMessage, which is used to reply
         to a specific FltSendMessage from the kernel (notification
         reply pattern).

    IMPORTANT: FilterGetMessage and FilterSendMessage CANNOT be called
    concurrently on the same port handle. The filter manager serializes
    access internally. If the listener thread is blocking on
    FilterGetMessage, a FilterSendMessage call will wait until the
    GetMessage completes. This is why we don't need to serialize our
    send/receive calls — the filter manager does it for us.

    However, there IS a subtle issue: if the listener thread is blocked
    on FilterGetMessage and we want to shut down, we can't just close
    the handle (that would cause FilterGetMessage to return with an
    error, which is actually what we want). So the shutdown sequence is:
      1. Set m_listenerRunning = false.
      2. Close the port handle (under lock).
      3. FilterGetMessage fails, listener thread exits.
      4. Join the listener thread.

Author:
    RansomShield Development
--*/

#include "CommManager.h"
#include <cstdio>

// ============================================================================
// SINGLETON
// ============================================================================

CommManager& CommManager::Instance()
{
    static CommManager instance;
    return instance;
}

CommManager::CommManager()
    : m_hPort(INVALID_HANDLE_VALUE)
    , m_connected(false)
    , m_listenerRunning(false)
    , m_sequenceNumber(0)
{
}

CommManager::~CommManager()
{
    StopListener();
    Disconnect();
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

HRESULT CommManager::Connect()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    //
    // Already connected? Nothing to do.
    //
    if (m_connected && m_hPort != INVALID_HANDLE_VALUE) {
        return S_OK;
    }

    //
    // FilterConnectCommunicationPort establishes a connection to the
    // minifilter driver's communication port.
    //
    // Parameters:
    //   lpPortName      - Port name (must match kernel's FltCreateCommunicationPort).
    //   dwOptions       - Reserved, must be 0.
    //   lpContext       - Optional connection context (we don't use one).
    //   dwContextSize   - Size of connection context (0 if no context).
    //   lpSecurityAttributes - Security attributes for the handle (NULL = default).
    //   hPort           - [out] Receives the connected port handle.
    //
    // The call blocks until the kernel's ConnectNotifyCallback completes.
    // If the driver is not loaded, this returns HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND).
    // If the caller lacks privilege, this returns ERROR_ACCESS_DENIED.
    //
    // IMPORTANT: The returned handle MUST be closed with CloseHandle()
    // when no longer needed. Do NOT use FltCloseClientPort() from user
    // mode — that's a kernel-only API.
    //
    HANDLE hPort = INVALID_HANDLE_VALUE;
    HRESULT hr = FilterConnectCommunicationPort(
        RS_PORT_NAME,
        0,                  // dwOptions (reserved)
        NULL,               // lpContext
        0,                  // dwContextSize
        NULL,               // lpSecurityAttributes
        &hPort              // [out] port handle
    );

    if (FAILED(hr)) {
        //
        // Common failure reasons:
        //   HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) - Driver not loaded.
        //   HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)  - Not an Administrator.
        //   HRESULT_FROM_WIN32(ERROR_INVALID_NAME)   - Bad port name.
        //
        fwprintf(stderr, L"RansomShield: FilterConnectCommunicationPort failed: 0x%08X\n", hr);

        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            fwprintf(stderr, L"  The RansomShield driver is not loaded. Install and start it first.\n");
        } else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
            fwprintf(stderr, L"  Access denied. Run as Administrator.\n");
        }

        m_hPort = INVALID_HANDLE_VALUE;
        m_connected = false;
        return hr;
    }

    m_hPort = hPort;
    m_connected = true;
    m_sequenceNumber = 0;

    wprintf(L"RansomShield: Connected to driver communication port.\n");
    return S_OK;
}

void CommManager::Disconnect()
{
    HANDLE hPortToClose = INVALID_HANDLE_VALUE;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_hPort != INVALID_HANDLE_VALUE) {
            hPortToClose = m_hPort;
            m_hPort = INVALID_HANDLE_VALUE;
            m_connected = false;
        }
    }

    //
    // Close the port handle OUTSIDE the lock.
    // Closing the handle while the listener thread is blocked on
    // FilterGetMessage will cause FilterGetMessage to return with an
    // error, which is exactly what we want for clean shutdown.
    //
    // After the handle is closed, the kernel's DisconnectNotifyCallback
    // is invoked, allowing the driver to clean up the client state.
    //
    if (hPortToClose != INVALID_HANDLE_VALUE) {
        CloseHandle(hPortToClose);
        wprintf(L"RansomShield: Disconnected from driver.\n");
    }
}

bool CommManager::IsConnected() const
{
    //
    // We use a const_cast here because std::mutex doesn't have a
    // const lock_guard constructor. This is safe because the lock
    // is protecting a read-only access pattern.
    //
    // Alternative: declare m_mutex as mutable.
    //
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_mutex));
    return m_connected && m_hPort != INVALID_HANDLE_VALUE;
}

// ============================================================================
// REQUEST/RESPONSE
// ============================================================================

HRESULT CommManager::SendRequest(
    _In_reads_bytes_(requestSize) const void* request,
    _In_ DWORD requestSize,
    _Out_writes_bytes_to_opt_(replySize, *bytesReturned) void* reply,
    _In_ DWORD replySize,
    _Out_opt_ DWORD* bytesReturned
)
{
    HANDLE hPort;

    //
    // Snapshot the port handle under the lock.
    // We release the lock BEFORE calling FilterSendMessage because:
    //   1. FilterSendMessage may block (waiting for the kernel callback).
    //   2. Holding the lock during a blocking call would deadlock the
    //      listener thread (which also acquires the lock to read m_hPort).
    //   3. The filter manager serializes send/receive internally, so
    //      concurrent sends are already prevented.
    //
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_connected || m_hPort == INVALID_HANDLE_VALUE) {
            return HRESULT_FROM_WIN32(ERROR_NOT_CONNECTED);
        }

        hPort = m_hPort;
    }

    DWORD localBytesReturned = 0;

    //
    // FilterSendMessage sends a request to the kernel driver and
    // optionally receives a reply.
    //
    // Parameters:
    //   hPort            - Port handle from FilterConnectCommunicationPort.
    //   lpInBuffer       - Request data to send.
    //   dwInBufferSize   - Size of request data.
    //   lpOutBuffer      - Buffer to receive the reply (may be NULL).
    //   dwOutBufferSize  - Size of reply buffer.
    //   lpBytesReturned  - [out] Actual bytes written to reply buffer.
    //
    // IMPORTANT: This call is serialized with FilterGetMessage by the
    // filter manager. If the listener thread is blocked on
    // FilterGetMessage, this call will wait until the GetMessage
    // completes (i.e., until a notification arrives or the port closes).
    //
    // In practice, this is rarely an issue because:
    //   - Notifications are infrequent (only when a PID is blocked).
    //   - The listener thread's FilterGetMessage returns quickly
    //     after receiving a notification.
    //   - If needed, use overlapped I/O for true concurrency.
    //
    HRESULT hr = FilterSendMessage(
        hPort,
        (LPVOID)request,
        requestSize,
        reply,
        replySize,
        &localBytesReturned
    );

    if (bytesReturned != NULL) {
        *bytesReturned = localBytesReturned;
    }

    if (FAILED(hr)) {
        //
        // Check if the driver disconnected. If so, mark us as disconnected.
        // The caller can check IsConnected() and attempt reconnection.
        //
        if (hr == HRESULT_FROM_WIN32(ERROR_FLT_INTERNAL_ERROR) ||
            hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
            hr == HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE)) {
            //
            // Driver went away or port was closed.
            //
            std::lock_guard<std::mutex> lock(m_mutex);
            m_connected = false;
            // Don't close m_hPort here; the listener thread or Disconnect handles that.
            fwprintf(stderr, L"RansomShield: Driver disconnected during send (0x%08X).\n", hr);
        }
    }

    return hr;
}

// ============================================================================
// NOTIFICATION LISTENER
// ============================================================================

HRESULT CommManager::StartListener(NotificationCallback callback)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_connected || m_hPort == INVALID_HANDLE_VALUE) {
            return HRESULT_FROM_WIN32(ERROR_NOT_CONNECTED);
        }

        if (m_listenerRunning) {
            return S_OK;  // Already running
        }

        m_callback = callback;
        m_listenerRunning = true;
    }

    //
    // Start the listener thread.
    // We use std::thread for simplicity. The thread runs ListenerThreadProc()
    // which loops on FilterGetMessage until m_listenerRunning is false.
    //
    try {
        m_listenerThread = std::thread(&CommManager::ListenerThreadProc, this);
    } catch (const std::system_error& e) {
        m_listenerRunning = false;
        fwprintf(stderr, L"RansomShield: Failed to start listener thread: %hs\n", e.what());
        return E_FAIL;
    }

    wprintf(L"RansomShield: Listener thread started.\n");
    return S_OK;
}

void CommManager::StopListener()
{
    //
    // Signal the listener thread to stop.
    // The atomic store ensures the thread sees the change promptly.
    //
    m_listenerRunning = false;

    //
    // Disconnect the port to unblock FilterGetMessage.
    // If the listener thread is blocked on FilterGetMessage, closing
    // the handle will cause it to return with an error, breaking the loop.
    //
    // We close the handle here, which means the caller needs to
    // reconnect after stopping the listener if they want to continue.
    //
    Disconnect();

    //
    // Wait for the listener thread to finish.
    // The thread should exit quickly after FilterGetMessage fails.
    //
    if (m_listenerThread.joinable()) {
        m_listenerThread.join();
    }

    wprintf(L"RansomShield: Listener thread stopped.\n");
}

void CommManager::ListenerThreadProc()
{
    //
    // Allocate the receive buffer. The buffer must accommodate:
    //   FILTER_MESSAGE_HEADER  (filled by the filter manager)
    //   + RS_NOTIFICATION_xxx  (our data)
    //
    // We use the largest possible notification structure as the buffer size.
    // All notification structures start with RS_MESSAGE_HEADER, so we can
    // inspect MessageType to determine the actual structure.
    //
    const DWORD bufferSize = sizeof(FILTER_MESSAGE_HEADER) + sizeof(RS_NOTIFICATION_BLOCKED_PID);
    BYTE* buffer = new (std::nothrow) BYTE[bufferSize];

    if (buffer == nullptr) {
        fwprintf(stderr, L"RansomShield: Listener thread: Out of memory for receive buffer.\n");
        m_listenerRunning = false;
        return;
    }

    wprintf(L"RansomShield: Listener thread entering message loop.\n");

    while (m_listenerRunning.load(std::memory_order_relaxed)) {
        //
        // Reset the buffer before each call. FilterGetMessage fills in
        // the FILTER_MESSAGE_HEADER at the beginning, followed by the
        // application data from the kernel's FltSendMessage call.
        //
        ZeroMemory(buffer, bufferSize);

        HANDLE hPort;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            hPort = m_hPort;
        }

        if (hPort == INVALID_HANDLE_VALUE) {
            //
            // Port was closed (Disconnect() was called). Exit the loop.
            //
            break;
        }

        //
        // FilterGetMessage retrieves the next pending notification from
        // the kernel driver.
        //
        // BLOCKING CALL: This function blocks until:
        //   1. A message arrives (kernel calls FltSendMessage), or
        //   2. The port is closed (driver unload, disconnect, or CloseHandle).
        //   3. An error occurs.
        //
        // Parameters:
        //   hPort            - Port handle.
        //   lpMessageBuffer  - Buffer to receive the message. MUST start
        //                      with FILTER_MESSAGE_HEADER.
        //   dwMessageBufferSize - Size of the buffer in bytes.
        //   lpOverlapped     - Overlapped structure for async I/O (NULL = sync).
        //
        // On success, the buffer layout is:
        //   [FILTER_MESSAGE_HEADER][RS_MESSAGE_HEADER][payload...]
        //
        HRESULT hr = FilterGetMessage(
            hPort,
            reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer),
            bufferSize,
            NULL    // lpOverlapped (synchronous)
        );

        if (!m_listenerRunning.load(std::memory_order_relaxed)) {
            //
            // StopListener() was called while we were waiting. Exit cleanly.
            //
            break;
        }

        if (FAILED(hr)) {
            //
            // Expected errors during shutdown:
            //   ERROR_INVALID_HANDLE  - Port was closed by Disconnect().
            //   ERROR_BROKEN_PIPE     - Driver unloaded.
            //   ERROR_FLT_INTERNAL_ERROR - Filter manager internal error.
            //
            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
                hr == HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE) ||
                hr == HRESULT_FROM_WIN32(ERROR_FLT_INTERNAL_ERROR)) {
                //
                // Port was closed. This is expected during shutdown.
                //
                if (m_listenerRunning.load()) {
                    fwprintf(stderr, L"RansomShield: Listener: Port closed unexpectedly (0x%08X).\n", hr);
                    //
                    // Mark as disconnected so the main thread knows.
                    //
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_connected = false;
                }
            } else {
                fwprintf(stderr, L"RansomShield: Listener: FilterGetMessage error 0x%08X\n", hr);
            }
            break;
        }

        //
        // Extract the application data from the buffer.
        // The FILTER_MESSAGE_HEADER is at offset 0. Our RS_MESSAGE_HEADER
        // and payload follow immediately after it.
        //
        const BYTE* appData = buffer + sizeof(FILTER_MESSAGE_HEADER);
        DWORD appDataSize = bufferSize - sizeof(FILTER_MESSAGE_HEADER);

        //
        // Dispatch to the registered callback.
        // The callback must not modify the buffer and must copy any data
        // it needs before returning (the buffer is reused for the next message).
        //
        if (m_callback) {
            try {
                m_callback(appData, appDataSize);
            } catch (const std::exception& e) {
                fwprintf(stderr, L"RansomShield: Exception in notification callback: %hs\n", e.what());
            } catch (...) {
                fwprintf(stderr, L"RansomShield: Unknown exception in notification callback.\n");
            }
        }
    }

    delete[] buffer;
    wprintf(L"RansomShield: Listener thread exiting.\n");
}

// ============================================================================
// CONVENIENCE METHODS
// ============================================================================

RS_MESSAGE_HEADER CommManager::MakeHeader(RS_MESSAGE_TYPE type, ULONG messageSize)
{
    RS_MESSAGE_HEADER header;
    ZeroMemory(&header, sizeof(header));
    header.MessageType = type;
    header.MessageSize = messageSize;
    header.ProtocolVersion = RS_PROTOCOL_VERSION;

    std::lock_guard<std::mutex> lock(m_mutex);
    header.SequenceNumber = m_sequenceNumber++;

    return header;
}

HRESULT CommManager::QueryBlockedPids(_Out_ RS_REPLY_BLOCKED_PIDS& reply)
{
    RS_REQUEST_BLOCKED_PIDS request;
    ZeroMemory(&request, sizeof(request));
    request.Header = MakeHeader(RsQueryBlockedPids, sizeof(request));

    DWORD bytesReturned = 0;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), &bytesReturned);

    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: QueryBlockedPids failed: 0x%08X\n", hr);
    }

    return hr;
}

HRESULT CommManager::QueryConfig(_Out_ RS_REPLY_CONFIG& reply)
{
    RS_REQUEST_QUERY_CONFIG request;
    ZeroMemory(&request, sizeof(request));
    request.Header = MakeHeader(RsQueryConfig, sizeof(request));

    DWORD bytesReturned = 0;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), &bytesReturned);

    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: QueryConfig failed: 0x%08X\n", hr);
    }

    return hr;
}

HRESULT CommManager::QueryAllowlist(_Out_ RS_REPLY_ALLOWLIST& reply)
{
    RS_REQUEST_QUERY_ALLOWLIST request;
    ZeroMemory(&request, sizeof(request));
    request.Header = MakeHeader(RsQueryAllowlist, sizeof(request));

    DWORD bytesReturned = 0;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), &bytesReturned);

    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: QueryAllowlist failed: 0x%08X\n", hr);
    }

    return hr;
}

HRESULT CommManager::UnblockPid(_In_ ULONG pid, _Out_ RS_REPLY_UNBLOCK_PID& reply)
{
    RS_REQUEST_UNBLOCK_PID request;
    ZeroMemory(&request, sizeof(request));
    request.Header = MakeHeader(RsRequestUnblockPid, sizeof(request));
    request.ProcessId = pid;

    DWORD bytesReturned = 0;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), &bytesReturned);

    if (SUCCEEDED(hr)) {
        if (reply.Status == 0) {
            wprintf(L"RansomShield: PID %lu unblocked successfully.\n", pid);
        } else {
            wprintf(L"RansomShield: PID %lu unblock failed (status=0x%08X).\n", pid, reply.Status);
        }
    }

    return hr;
}

HRESULT CommManager::UpdateConfig(
    _In_ ULONG fileCountThreshold,
    _In_ ULONG timeWindowSeconds,
    _In_ BOOLEAN monitoringEnabled
)
{
    RS_REQUEST_UPDATE_CONFIG request;
    ZeroMemory(&request, sizeof(request));
    request.Header = MakeHeader(RsUpdateConfig, sizeof(request));
    request.FileCountThreshold = fileCountThreshold;
    request.TimeWindowSeconds = timeWindowSeconds;
    request.MonitoringEnabled = monitoringEnabled;

    RS_REPLY_GENERIC reply;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), NULL);

    if (SUCCEEDED(hr) && reply.Status == 0) {
        wprintf(L"RansomShield: Configuration updated (threshold=%lu, window=%lu, monitoring=%s).\n",
                fileCountThreshold, timeWindowSeconds,
                monitoringEnabled ? L"enabled" : L"disabled");
    } else {
        fwprintf(stderr, L"RansomShield: UpdateConfig failed (hr=0x%08X, status=0x%08X).\n", hr, reply.Status);
    }

    return hr;
}

HRESULT CommManager::PauseMonitoring()
{
    RS_REQUEST_PAUSE request;
    ZeroMemory(&request, sizeof(request));
    request.Header = MakeHeader(RsRequestPause, sizeof(request));

    RS_REPLY_GENERIC reply;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), NULL);

    if (SUCCEEDED(hr) && reply.Status == 0) {
        wprintf(L"RansomShield: Monitoring paused.\n");
    } else {
        fwprintf(stderr, L"RansomShield: Pause failed (hr=0x%08X, status=0x%08X).\n", hr, reply.Status);
    }

    return hr;
}

HRESULT CommManager::ResumeMonitoring()
{
    RS_REQUEST_RESUME request;
    ZeroMemory(&request, sizeof(request));
    request.Header = MakeHeader(RsRequestResume, sizeof(request));

    RS_REPLY_GENERIC reply;
    ZeroMemory(&reply, sizeof(reply));

    HRESULT hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), NULL);

    if (SUCCEEDED(hr) && reply.Status == 0) {
        wprintf(L"RansomShield: Monitoring resumed.\n");
    } else {
        fwprintf(stderr, L"RansomShield: Resume failed (hr=0x%08X, status=0x%08X).\n", hr, reply.Status);
    }

    return hr;
}

HRESULT CommManager::PushAllowlist(_In_ const std::vector<std::wstring>& entries)
{
    HRESULT hr;

    //
    // STEP 1: Clear the driver's existing allowlist.
    // This ensures stale entries are removed before we push the new list.
    //
    RS_REQUEST_CLEAR_ALLOWLIST clearReq;
    ZeroMemory(&clearReq, sizeof(clearReq));
    clearReq.Header = MakeHeader(RsClearAllowlist, sizeof(clearReq));

    RS_REPLY_GENERIC clearReply;
    ZeroMemory(&clearReply, sizeof(clearReply));

    hr = SendRequest(&clearReq, sizeof(clearReq), &clearReply, sizeof(clearReply), NULL);
    if (FAILED(hr)) {
        fwprintf(stderr, L"RansomShield: ClearAllowlist failed: 0x%08X\n", hr);
        return hr;
    }

    //
    // STEP 2: Determine the push strategy.
    // If the list fits in one message (<= RS_MAX_ALLOWLIST_ENTRIES), use
    // the full push message. Otherwise, send in chunks.
    //
    if (entries.size() <= RS_MAX_ALLOWLIST_ENTRIES) {
        //
        // FULL PUSH: Send the entire allowlist in one message.
        //
        RS_REQUEST_UPDATE_ALLOWLIST_FULL request;
        ZeroMemory(&request, sizeof(request));
        request.Header = MakeHeader(RsUpdateAllowlistFull, sizeof(request));
        request.EntryCount = static_cast<ULONG>(entries.size());

        for (size_t i = 0; i < entries.size() && i < RS_MAX_ALLOWLIST_ENTRIES; i++) {
            //
            // Copy each entry. wcsncpy_s ensures no buffer overflow and
            // null-terminates the destination string.
            //
            wcsncpy_s(request.Entries[i], RS_MAX_ALLOWLIST_NAME_LEN,
                      entries[i].c_str(), _TRUNCATE);
        }

        RS_REPLY_GENERIC reply;
        ZeroMemory(&reply, sizeof(reply));

        hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), NULL);

        if (SUCCEEDED(hr) && reply.Status == 0) {
            wprintf(L"RansomShield: Allowlist pushed (%zu entries, full).\n", entries.size());
        }
    } else {
        //
        // CHUNKED PUSH: Send the allowlist in multiple chunks.
        // Each chunk contains up to RS_MAX_ALLOWLIST_CHUNK entries.
        // The driver appends each chunk to its internal list.
        //
        size_t totalChunks = (entries.size() + RS_MAX_ALLOWLIST_CHUNK - 1) / RS_MAX_ALLOWLIST_CHUNK;

        for (size_t chunkIdx = 0; chunkIdx < totalChunks; chunkIdx++) {
            RS_REQUEST_UPDATE_ALLOWLIST_CHUNK request;
            ZeroMemory(&request, sizeof(request));
            request.Header = MakeHeader(RsUpdateAllowlistChunk, sizeof(request));
            request.ChunkIndex = static_cast<ULONG>(chunkIdx);
            request.ChunkCount = static_cast<ULONG>(totalChunks);

            size_t startIdx = chunkIdx * RS_MAX_ALLOWLIST_CHUNK;
            size_t endIdx = min(startIdx + RS_MAX_ALLOWLIST_CHUNK, entries.size());
            request.EntryCount = static_cast<ULONG>(endIdx - startIdx);

            for (size_t i = startIdx; i < endIdx; i++) {
                size_t localIdx = i - startIdx;
                wcsncpy_s(request.Entries[localIdx], RS_MAX_ALLOWLIST_NAME_LEN,
                          entries[i].c_str(), _TRUNCATE);
            }

            RS_REPLY_GENERIC reply;
            ZeroMemory(&reply, sizeof(reply));

            hr = SendRequest(&request, sizeof(request), &reply, sizeof(reply), NULL);

            if (FAILED(hr)) {
                fwprintf(stderr, L"RansomShield: Allowlist chunk %zu/%zu failed: 0x%08X\n",
                         chunkIdx + 1, totalChunks, hr);
                return hr;
            }

            if (reply.Status != 0) {
                fwprintf(stderr, L"RansomShield: Allowlist chunk %zu/%zu rejected (0x%08X).\n",
                         chunkIdx + 1, totalChunks, reply.Status);
                return hr;
            }
        }

        wprintf(L"RansomShield: Allowlist pushed (%zu entries, %zu chunks).\n",
                entries.size(), totalChunks);
    }

    return hr;
}
