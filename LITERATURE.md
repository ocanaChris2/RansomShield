# RansomShield — Technical Deep Dive

This document explains how RansomShield works from first principles, connecting
every design decision to the underlying systems literature, OS internals, and
security research that motivates it. Code excerpts are taken verbatim from the
source tree and annotated inline.

---

## Table of Contents

1. [The Ransomware Problem](#1-the-ransomware-problem)
2. [Windows I/O Architecture — The Foundation](#2-windows-io-architecture--the-foundation)
3. [The Filter Manager and Minifilters](#3-the-filter-manager-and-minifilters)
4. [Driver Registration and the Altitude System](#4-driver-registration-and-the-altitude-system)
5. [Heuristic Detection — Sliding Window Rate Limiting](#5-heuristic-detection--sliding-window-rate-limiting)
6. [Per-PID Hash Table — Data Structure Design](#6-per-pid-hash-table--data-structure-design)
7. [Ring Buffer for Timestamps](#7-ring-buffer-for-timestamps)
8. [IRQL, Spinlocks, and Non-Paged Pool](#8-irql-spinlocks-and-non-paged-pool)
9. [Double-Checked Locking for Context Creation](#9-double-checked-locking-for-context-creation)
10. [The Allowlist — False Positive Suppression](#10-the-allowlist--false-positive-suppression)
11. [Kernel–User Communication Port](#11-kerneluser-communication-port)
12. [The Sticky-Block Model](#12-the-sticky-block-model)
13. [User-Mode Client Architecture](#13-user-mode-client-architecture)
14. [Tray Agent — Background Notification Daemon](#14-tray-agent--background-notification-daemon)
15. [Security Threat Model](#15-security-threat-model)
16. [Design Tradeoffs and Limitations](#16-design-tradeoffs-and-limitations)
17. [References](#17-references)

---

## 1. The Ransomware Problem

Ransomware is malware that encrypts a victim's files and demands payment for
the decryption key. The canonical attack pattern is:

1. Enumerate files of interest (`.docx`, `.jpg`, `.db`, etc.)
2. Open each file for reading
3. Read plaintext into memory
4. Encrypt in memory with an asymmetric or symmetric key
5. Overwrite the file with ciphertext (`IRP_MJ_WRITE`)
6. Optionally rename the file with a marker extension (`.locked`, `.crypt`)
7. Optionally delete shadow copies to prevent volume-based recovery

Steps 5 and 6 are the destructive steps — and both involve file system
operations observable by a kernel driver.

Empirical studies of real-world ransomware families (WannaCry, CryptoLocker,
Ryuk, Conti) show a defining behavioral signature: **a single process performs
hundreds to thousands of file writes or renames in a short time span** [Kharraz
et al., 2016; Continella et al., 2016]. This distinguishes ransomware from any
normal user workload.

RansomShield exploits this property through a *behavioral heuristic* evaluated
entirely in kernel space, with zero dependence on signature databases or network
connectivity.

---

## 2. Windows I/O Architecture — The Foundation

Every file operation in Windows travels through a layered I/O stack rooted in
the I/O Manager. A user-mode `WriteFile()` call is translated into an
**I/O Request Packet (IRP)** that descends the stack from the top-level file
system driver down to the disk miniport.

```
User-Mode App
    │  WriteFile()
    ▼
I/O Manager (creates IRP_MJ_WRITE IRP)
    │
    ▼
[RansomShield minifilter]  ← intercepts here
    │
    ▼
NTFS / FAT32 (file system driver)
    │
    ▼
Disk class driver → storage miniport → physical disk
```

**IRPs** carry all parameters for an I/O request. An IRP has a fixed header
(`_IRP`) and an array of stack locations (`IO_STACK_LOCATION`), one per driver
in the stack. Each driver reads and may modify its own stack location.

The relevant IRP major codes intercepted by RansomShield are:

| IRP Major Code | Meaning | Ransomware relevance |
|---|---|---|
| `IRP_MJ_WRITE` | Write data to a file | Overwrites plaintext with ciphertext |
| `IRP_MJ_SET_INFORMATION` | Change file metadata | Renames (extension change) or deletes files |

References: [Russinovich et al., 2017, Ch. 6 "I/O System"]; [Reimer et al., 2008].

---

## 3. The Filter Manager and Minifilters

The **Filter Manager** (`FltMgr.sys`) is a Microsoft-provided kernel component
that implements a clean registration model for file system filters. Before
Filter Manager (pre-Windows XP SP2), writing a file system filter required
attaching a device object to each volume and handling all IRP types — a
notoriously error-prone process that caused countless system crashes.

With the minifilter model:

- A driver calls `FltRegisterFilter()` once at `DriverEntry` time, passing a
  `FLT_REGISTRATION` structure that declares callbacks and an altitude.
- Filter Manager inserts the minifilter into its internal stack at the declared
  altitude.
- For each I/O operation, Filter Manager calls the minifilter's **pre-callback**
  before the I/O reaches the file system, and an optional **post-callback**
  after the file system completes it.

From `RansomShield.c:255`:

```c
const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    g_ContextRegistration,     // context types registered
    g_Callbacks,               // I/O callback table
    RsUnloadCallback,          // called on fltmc unload
    RsInstanceSetupCallback,   // called when attaching to a volume
    ...
};
```

The callback table `g_Callbacks` (`RansomShield.c:134`) lists only the two
operation types that matter:

```c
const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    {
        IRP_MJ_WRITE,
        FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
        RsPreOperationWrite,
        NULL,           // no post-callback needed
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        RsPreOperationSetInformation,
        RsPostOperationSetInformation,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};
```

The `FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO` flag on `IRP_MJ_WRITE` is
critical: it tells Filter Manager not to deliver write callbacks for **paging
I/O** — writes issued by the Memory Manager when flushing dirty pages to disk.
Intercepting paging I/O and returning errors would cause an immediate blue
screen (`IRQL_NOT_LESS_OR_EQUAL` or `KMODE_EXCEPTION_NOT_HANDLED`).

Reference: [Oney, 2003, "Programming the Microsoft Windows Driver Model"];
[Microsoft WDK documentation, "FLT_OPERATION_REGISTRATION"].

---

## 4. Driver Registration and the Altitude System

The **altitude** is a numeric string that determines the vertical position of a
minifilter in the filter stack. Higher numbers mean closer to user mode; lower
numbers mean closer to the disk. Multiple filters at the same altitude are not
permitted.

Microsoft allocates altitude ranges for specific filter categories. The
anti-virus range is **320000–329999**, reflecting the intention that AV filters
intercept I/O *above* encryption and below general-purpose filters.

```c
// RansomShield.h:77
#define RS_ALTITUDE  L"325010"
```

RansomShield at 325010 sits near the middle of the AV range. This means:

- It sees I/O **after** lower-altitude encryption products have had a chance to
  operate (they would operate on already-encrypted data; we see the original).
- It sees I/O **before** higher-altitude scanners like Windows Defender.

The altitude is declared in the INF file, not in code, and is matched at driver
load time by Filter Manager.

Reference: [Microsoft, "Allocated filter altitudes",
docs.microsoft.com/windows-hardware/drivers/ifs/allocated-altitudes].

---

## 5. Heuristic Detection — Sliding Window Rate Limiting

The detection algorithm is a **sliding window counter**: for each process, we
count how many monitored file operations occurred within the last *T* seconds.
If that count exceeds threshold *K*, the process is flagged as ransomware.

```
Default parameters (SharedDefs.h):
  K = 50 operations
  T = 10 seconds
```

**Why a sliding window rather than a fixed-epoch counter?**

A fixed-epoch counter (reset every 10 seconds) is vulnerable to a *boundary
attack*: malware that knows the reset cycle can perform 49 operations in the
last second of each epoch, totaling 490 operations per 10-second period without
ever tripping the threshold. A sliding window eliminates this attack surface
because at every moment, only the operations in the last *T* seconds count.

This principle is identical to the *token bucket* and *sliding window log*
algorithms studied in network rate limiting [Tanenbaum & Wetherall, 2011,
"Computer Networks", Ch. 5.3]. RansomShield uses the *sliding window log*
variant because individual timestamps are needed to correctly exclude old
events.

The algorithm in pseudocode:

```
on_file_operation(pid):
    now = current_time()
    context = get_or_create_context(pid)
    prune_old(context, now)      // remove timestamps older than T
    add_timestamp(context, now)
    if count(context) >= K:
        block(pid)
        notify_user_mode(pid)
```

In practice (`Context.c:557–811`), the precise count of operations within the
window is computed by walking the ring buffer:

```c
// Context.c:718–739
recentCount = 0;
idx = (context->OperationHead + RS_MAX_OPERATIONS_PER_PID
       - context->OperationCount) % RS_MAX_OPERATIONS_PER_PID;

for (i = 0; i < count; i++) {
    if ((currentTime - context->Operations[idx].Timestamp) <= g_TimeWindowTicks) {
        recentCount++;
    }
    idx = (idx + 1) % RS_MAX_OPERATIONS_PER_PID;
}
```

**Timestamps** are obtained via `KeQueryInterruptTime()`, which returns a
64-bit count of 100-nanosecond intervals since system boot. One second equals
10,000,000 ticks. This clock is monotonically increasing, queryable at any
IRQL, and immune to wall-clock adjustments (NTP, DST) — all critical properties
for a security measurement.

Reference: [Kharraz et al., 2016, "UNVEIL: A Large-Scale, Automated Approach
to Detecting Ransomware"]; [Continella et al., 2016, "ShieldFS: A
Self-Healing, Ransomware-Aware Filesystem"].

---

## 6. Per-PID Hash Table — Data Structure Design

Tracking up to 1,024 processes simultaneously requires a data structure with
O(1) average-case lookup. RansomShield uses an open-addressed **separate
chaining hash table** over a fixed array of 1,021 buckets.

```c
// RansomShield.h:256
#define RS_HASH_TABLE_SIZE  1021  // prime number for good distribution

// Context.c:63
LIST_ENTRY  g_ContextHashTable[RS_HASH_TABLE_SIZE];
```

**Why 1,021 (prime)?**

Windows PIDs are always multiples of 4 (the `EPROCESS` structure is aligned to
a 4-byte boundary and PIDs are assigned sequentially in steps of 4). If the
table size were a power of 2 (say, 1,024), then `PID % 1024` would always fall
in multiples of 4: buckets 0, 4, 8, ... would be densely populated while odd
buckets would be empty. A prime modulus breaks this alignment artifact,
distributing PIDs far more evenly [Knuth, 1998, "The Art of Computer
Programming", Vol. 3, §6.4].

The hash function is the identity modulo (`Context.c:293`):

```c
static ULONG RsHashProcessId(_In_ ULONG ProcessId) {
    return ProcessId % RS_HASH_TABLE_SIZE;
}
```

For production use, a multiplicative hash (`PID * 2654435761 >> (32 - log2(N))`)
derived from the golden ratio would provide better statistical distribution even
for non-random inputs [Knuth, 1998].

**Separate chaining** stores colliding entries in a linked list at each bucket.
Windows provides `LIST_ENTRY`, a doubly-linked circular list embedded directly
in the structures being linked. The `CONTAINING_RECORD` macro recovers the
enclosing structure from a pointer to the embedded link:

```c
// Context.c:345–349
for (entry = listHead->Flink; entry != listHead; entry = entry->Flink) {
    context = CONTAINING_RECORD(entry, RS_PROCESS_CONTEXT, Link);
    if (context->ProcessId == ProcessId) {
        return context;
    }
}
```

`LIST_ENTRY` uses a circular sentinel (the list head itself serves as both the
first and last node's neighbor), so the empty-list check is simply
`IsListEmpty(head)` and iteration terminates when `entry == listHead`. This
pattern is ubiquitous in the Windows kernel and documented in [Russinovich et
al., 2017, Ch. 4 "Management Mechanisms"].

---

## 7. Ring Buffer for Timestamps

Each `RS_PROCESS_CONTEXT` stores up to 256 operation timestamps in a **circular
buffer** (ring buffer):

```c
// RansomShield.h:130–132, 192–196
typedef struct _RS_PROCESS_CONTEXT {
    ...
    RS_OPERATION_ENTRY  Operations[RS_MAX_OPERATIONS_PER_PID]; // 256 entries
    ULONG               OperationHead;    // next write position
    ULONG               OperationCount;  // valid entries
    ...
} RS_PROCESS_CONTEXT;
```

A ring buffer avoids the O(n) cost of shifting elements in a linear array when
pruning expired entries. The oldest element is always at index:

```
oldest = (OperationHead - OperationCount + MAX) % MAX
```

Writing a new timestamp (`Context.c:684–702`):

```c
// Buffer not yet full: simple append
context->Operations[context->OperationHead].Timestamp = currentTime;
context->OperationHead = (context->OperationHead + 1) % RS_MAX_OPERATIONS_PER_PID;
context->OperationCount++;

// Buffer full: overwrite oldest entry and advance head
context->Operations[context->OperationHead].Timestamp = currentTime;
context->OperationHead = (context->OperationHead + 1) % RS_MAX_OPERATIONS_PER_PID;
// OperationCount stays at MAX
```

**Pruning** removes timestamps that have fallen outside the sliding window.
Because the ring buffer wraps around, naive in-place compaction is dangerous
(reading from a later index while writing to an earlier one can overwrite unread
entries). The solution (`Context.c:831–889`) is to compact into a temporary
stack buffer, then copy back:

```c
RS_OPERATION_ENTRY tempBuffer[RS_MAX_OPERATIONS_PER_PID];
ULONG readIdx = (Context->OperationHead + RS_MAX_OPERATIONS_PER_PID
                 - Context->OperationCount) % RS_MAX_OPERATIONS_PER_PID;
ULONG newCount = 0;

for (i = 0; i < Context->OperationCount; i++) {
    if ((CurrentTime - Context->Operations[readIdx].Timestamp) <= g_TimeWindowTicks)
        tempBuffer[newCount++] = Context->Operations[readIdx];
    readIdx = (readIdx + 1) % RS_MAX_OPERATIONS_PER_PID;
}
RtlCopyMemory(Context->Operations, tempBuffer, newCount * sizeof(RS_OPERATION_ENTRY));
Context->OperationCount = newCount;
Context->OperationHead  = newCount % RS_MAX_OPERATIONS_PER_PID;
```

The temporary buffer is `256 × 8 = 2,048` bytes on the kernel stack. Default
kernel stack size on x64 Windows is 24 KB, so this is safe. Reference:
[Russinovich et al., 2017, "Windows Internals Part 1", Thread Stack section].

---

## 8. IRQL, Spinlocks, and Non-Paged Pool

**Interrupt Request Level (IRQL)** is the Windows kernel's priority scheme for
hardware and software interrupt servicing. The three IRQLs relevant here are:

| IRQL | Level | Constraints |
|---|---|---|
| `PASSIVE_LEVEL` (0) | Normal kernel and user-mode code | No constraints |
| `APC_LEVEL` (1) | Asynchronous Procedure Calls | No page faults |
| `DISPATCH_LEVEL` (2) | DPCs, spinlocks held | No page faults, no blocking waits |

When a spinlock is acquired with `KeAcquireSpinLock`, the processor's IRQL is
raised to `DISPATCH_LEVEL`. At `DISPATCH_LEVEL`, the thread scheduler cannot
run on this CPU, so **no blocking or sleeping** is allowed, and any access to
**pageable memory** causes an immediate blue screen.

This is why every `RS_PROCESS_CONTEXT` must be allocated from
`NonPagedPoolNx` — the non-pageable, non-executable kernel heap:

```c
// Context.c:421–425
context = (PRS_PROCESS_CONTEXT)ExAllocatePool2(
    POOL_FLAG_NON_PAGED,            // Non-executable non-paged pool
    sizeof(RS_PROCESS_CONTEXT),
    RS_POOL_TAG                     // 'hSsR' for pool tracking
);
```

`ExAllocatePool2` (WDK 2004+) replaces the older `ExAllocatePoolWithTag`; it
zero-initializes the allocation, which prevents information leaks from prior
allocations [Microsoft Security Development Lifecycle requirement].

The `NonPagedPoolNx` (no-execute) variant is required for **HVCI
(Hypervisor-Protected Code Integrity)**, a Windows 11 feature that uses the
hypervisor to prevent kernel data from being executed as code. Using the
older `NonPagedPool` (executable) will fail on HVCI-enabled systems.

The global spinlock is initialized at driver load time and protects the entire
hash table:

```c
// Context.c:190
KeInitializeSpinLock(&g_ContextLock);

// Acquisition pattern (any function that touches the table):
KIRQL oldIrql;
KeAcquireSpinLock(&g_ContextLock, &oldIrql);
// ... critical section: pointer ops, counter increments ...
KeReleaseSpinLock(&g_ContextLock, oldIrql);
```

`oldIrql` captures the IRQL before the lock was acquired; `KeReleaseSpinLock`
restores it. This allows callers at `PASSIVE_LEVEL` or `APC_LEVEL` to use the
lock safely without permanently elevating the IRQL.

**Single global lock vs. per-bucket locks**: RansomShield uses one lock for the
entire hash table. Per-bucket locking would allow parallel operations on
different buckets but multiplies lock memory and complexity. For the expected
workload — a file operation per I/O request, not thousands per microsecond — a
single lock is adequate. The critical section under the lock is intentionally
minimal: pointer traversal, counter increment, timestamp write.

Reference: [Russinovich et al., 2017, "Windows Internals Part 1", Ch. 3
"System Mechanisms"]; [Corbet et al., 2005, "Linux Device Drivers", Ch. 5
"Concurrency and Race Conditions" — for comparison with the Linux spinlock
model].

---

## 9. Double-Checked Locking for Context Creation

Memory allocation (`ExAllocatePool2`) cannot be called while holding a
spinlock at `DISPATCH_LEVEL`. But the hash table lookup and context insertion
must be atomic. The solution is **double-checked locking** (DCL):

```
Phase 1 — Fast path (under lock):
  1. Acquire spinlock.
  2. Look up PID in hash table.
  3a. Found: record operation, release lock.
  3b. Not found: release lock, proceed to allocation.

Phase 2 — Slow path (no lock, then recheck):
  4. Allocate new context at PASSIVE_LEVEL (no lock held).
  5. Re-acquire spinlock.
  6. Look up PID again (another thread may have won the race).
  6a. Found: free our allocation, use theirs, record operation.
  6b. Still not found: insert our new context, record operation.
  7. Release lock.
```

From `Context.c:590–669`:

```c
// Phase 1
KeAcquireSpinLock(&g_ContextLock, &oldIrql);
context = RsLookupProcessContext(ProcessId, &bucketHead);
if (context != NULL) {
    // fast path: context exists
    goto RecordAndEvaluate;
}
KeReleaseSpinLock(&g_ContextLock, oldIrql);

// Phase 2 — allocate outside the lock
newContext = RsCreateProcessContext(ProcessId, ProcessImageName);

// Re-acquire and re-check (DCL pattern)
KeAcquireSpinLock(&g_ContextLock, &oldIrql);
context = RsLookupProcessContext(ProcessId, &bucketHead);
if (context != NULL) {
    ExFreePoolWithTag(newContext, RS_POOL_TAG);  // lost the race, discard
} else {
    context = newContext;
    InsertHeadList(bucketHead, &context->Link);
    g_TrackedPidCount++;
}
```

DCL is well-studied in concurrent programming [Lea, 1999; Schmidt, 2000]. The
kernel variant here is simpler than the user-mode Java/C++ version because the
spinlock provides the necessary memory barrier — `KeAcquireSpinLock` issues an
`MFENCE`-equivalent on x86-64, ensuring all preceding writes are visible to
other processors before the lock is taken.

---

## 10. The Allowlist — False Positive Suppression

Behavioral heuristics suffer from false positives: antivirus engines, backup
software, and search indexers all perform bulk file I/O. Without an allowlist,
these would be blocked within seconds of driver load.

RansomShield maintains two allowlists:

**Static allowlist** (compile-time, in `.rdata` — always non-paged):

```c
// Context.c:116–127
static const WCHAR g_AllowList_Names[RS_ALLOWLIST_COUNT][RS_MAX_IMAGE_NAME_LEN] = {
    L"svchost.exe",
    L"SearchIndexer.exe",
    L"MsMpEng.exe",           // Windows Defender
    L"TrustedInstaller.exe",
    L"System",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"services.exe",
    L"dwm.exe"
};
```

**Dynamic allowlist** (user-pushed at runtime, protected by `g_ContextLock`):
up to 128 entries, stored in a `WCHAR` array in the driver's `.data` section
(non-paged as part of the driver image).

Matching extracts only the *filename* component (after the last backslash) from
the full process image path, then compares case-insensitively:

```c
// Context.c:1054–1078
lastBackslash = ProcessImageName->Buffer;
for (i = 0; i < ProcessImageName->Length / sizeof(WCHAR); i++) {
    if (ProcessImageName->Buffer[i] == L'\\')
        lastBackslash = &ProcessImageName->Buffer[i + 1];
}
// Build a UNICODE_STRING for just the filename portion
processFileName.Buffer = lastBackslash;
processFileName.Length = ...;

// Case-insensitive comparison (TRUE = ignore case)
if (RtlEqualUnicodeString(&processFileName, &g_Allowlist[i], TRUE))
    return TRUE;
```

The image name is obtained via `SeLocateProcessImageName()`, which returns a
`UNICODE_STRING` pointing into the `EPROCESS` quota block (pageable memory).
The driver deep-copies this into the non-paged context buffer at `PASSIVE_LEVEL`,
before the spinlock is acquired.

Reference: [Kharraz et al., 2016] notes that false-positive suppression is
one of the key engineering challenges for behavioral AV — static allowlists
alone are insufficient for enterprise environments; dynamic allowlists populated
from administrator configuration are necessary.

---

## 11. Kernel–User Communication Port

The **FltMgr communication port** is a named IPC mechanism specific to filter
drivers. It provides a bidirectional channel between a kernel minifilter and a
user-mode client.

Architecture (from `CommPort.c:15–31`):

```
User-Mode                                   Kernel Mode
─────────                                   ───────────
FilterConnectCommunicationPort() ──────►   RsConnectNotifyCallback()
                                                (store g_ClientPort)

FilterGetMessage()  ◄───────────────   FltSendMessage()
     (listener thread)                     (push notification on block)

FilterSendMessage(query)  ──────────►  RsMessageNotifyCallback()
     ◄──────────────────────────────       (return reply in OutputBuffer)
```

The server port is created with `FltCreateCommunicationPort()`:

```c
// CommPort.c:216–225
status = FltCreateCommunicationPort(
    FilterHandle,
    &g_ServerPort,
    &oa,                           // OBJECT_ATTRIBUTES with security descriptor
    NULL,
    RsConnectNotifyCallback,
    RsDisconnectNotifyCallback,
    RsMessageNotifyCallback,
    1                              // MaxConnections = 1 (single client)
);
```

`MaxConnections = 1` enforces the single-client design: while the tray agent
holds the port, CLI commands cannot connect simultaneously. This is a deliberate
architectural constraint — having two clients simultaneously would create race
conditions in `FltSendMessage` target selection.

**Push notifications** (kernel → user) use `FltSendMessage()` after releasing
the spinlock. The call must be at `PASSIVE_LEVEL` because it may block until
the user-mode client reads the message. A 5-second timeout prevents indefinite
blocking of the I/O path:

```c
// CommPort.c:113
LARGE_INTEGER g_MessageTimeout = {.QuadPart = -5 * 10000000}; // 5 seconds, relative
```

Negative `LARGE_INTEGER` values are interpreted as relative time (duration) by
the NT kernel, as opposed to positive values which are absolute FILETIME. The
unit is 100-nanosecond intervals, so 5 seconds = 5 × 10,000,000 = 50,000,000
units.

**Use-after-free prevention**: after releasing `g_ContextLock`, the `context`
pointer may be freed by a concurrent `RsUnblockProcess()` call. All data needed
for the notification is therefore copied to stack-local variables **before**
releasing the lock:

```c
// Context.c:754–778
WCHAR localImageName[RS_MAX_IMAGE_NAME_LEN];
LONGLONG localBlockedTimestamp = 0;
BOOLEAN localShouldNotify = FALSE;

if (recentCount >= g_FileCountThreshold && !context->IsBlocked) {
    context->IsBlocked = TRUE;
    context->BlockedTimestamp = currentTime;
    localShouldNotify = TRUE;
    RtlCopyMemory(localImageName, context->ImageName, sizeof(localImageName));
    localBlockedTimestamp = context->BlockedTimestamp;
}

KeReleaseSpinLock(&g_ContextLock, oldIrql);

// Safe: using local copies, not the (possibly freed) context pointer
if (localShouldNotify)
    RsSendBlockNotification(ProcessId, localImageName, localBlockedTimestamp, recentCount);
```

**Message protocol**: all messages begin with `RS_MESSAGE_HEADER` (type, size,
sequence number, protocol version). The type namespace is partitioned:

| Range | Direction | Purpose |
|---|---|---|
| 1–99 | Kernel → User | Unsolicited notifications |
| 100–199 | User → Kernel | Queries (request/reply) |
| 200–299 | User → Kernel | Commands |
| 300–399 | User → Kernel | Configuration |

This partitioning allows a listener to distinguish push notifications from
replies without maintaining per-request correlation state.

Reference: [Solomon & Russinovich, 2000, "Inside Windows 2000", Filter Manager
chapter]; [Microsoft WDK, "FltCreateCommunicationPort" documentation].

---

## 12. The Sticky-Block Model

Once a process is flagged (`context->IsBlocked = TRUE`), **all subsequent
write, rename, and delete operations from that PID are blocked immediately**,
without re-evaluating the heuristic:

```c
// Context.c:596–602
if (context->IsBlocked) {
    *ShouldBlock = TRUE;
    KeReleaseSpinLock(&g_ContextLock, oldIrql);
    return STATUS_SUCCESS;
}
```

The block is "sticky" — it is **not** automatically cleared when the operation
rate drops below the threshold. Clearing requires an explicit administrator
action via the communication port (`RsRequestUnblockPid`).

**Why sticky?** If the block were automatically lifted after the rate dropped,
a sophisticated ransomware could throttle itself to encrypt 49 files every 10
seconds (just below threshold), never tripping the detector while still
encrypting ~300 files per minute. Sticky blocking eliminates this evasion
entirely. Once blocked, the process remains blocked regardless of subsequent
behavior.

The only ways to unblock are:
1. An administrator sends `RsRequestUnblockPid` via the CLI or tray agent.
2. The driver is unloaded (`RsDestroyContextTracking` frees all contexts).
3. The machine reboots.

This philosophy is consistent with the "fail-safe defaults" principle from
[Saltzer & Schroeder, 1975]: **it is safer to stay in the blocked state by
default than to return to unmonitored operation**.

---

## 13. User-Mode Client Architecture

`RansomShieldClient.exe` is a C++ CLI tool and daemon. It communicates with the
kernel driver via `FilterConnectCommunicationPort()` / `FilterSendMessage()` /
`FilterGetMessage()`.

Key components:

| File | Responsibility |
|---|---|
| `Main.cpp` | CLI argument dispatch; daemon loop (60s health check) |
| `CommManager.h/.cpp` | Singleton wrapper around the filter port; listener thread |
| `ConfigManager.h/.cpp` | Registry persistence (`HKLM\...\RansomShield\Config`) |
| `EventLogger.h/.cpp` | Windows Event Log via `ReportEvent()` |
| `SharedDefs.h` | Shared protocol structures |

**Listener thread**: `CommManager` runs a background thread that calls
`FilterGetMessage()` in a loop. When the kernel calls `FltSendMessage()` with a
`RsNotifyBlockedPid` notification, the listener thread wakes and dispatches the
notification to the registered handler (which logs to Event Log, prints to
console, or triggers a tray balloon).

**Registry persistence**: `ConfigManager` stores the configured thresholds and
the allowlist in the registry at:

```
HKLM\SYSTEM\CurrentControlSet\Services\RansomShield\Config\
    FileCountThreshold  (DWORD)
    TimeWindowSeconds   (DWORD)
    MonitoringEnabled   (DWORD)

HKLM\SYSTEM\CurrentControlSet\Services\RansomShield\Allowlist\
    Entry00  (SZ) = "svchost.exe"
    Entry01  (SZ) = "backup.exe"
    ...
```

On startup, the service reads these values and pushes them to the driver via
`RsUpdateConfig` and `RsUpdateAllowlistFull`. This ensures the driver's
runtime state survives service restarts without requiring hard-coded defaults.

**Fail-open vs. fail-closed**: when the context allocation fails (OOM), the
driver chooses **fail-open** (allow the write through):

```c
// RansomShield.c:773–781
// We choose FAIL-OPEN here because:
//   1. False positives (blocking legitimate I/O) are very disruptive.
//   2. A transient OOM condition shouldn't lock out the system.
//   3. The heuristic will catch the process on the next operation.
return FLT_PREOP_SUCCESS_NO_CALLBACK;
```

This is a deliberate availability vs. security tradeoff — production-grade
security products typically choose fail-closed for kernel drivers but fail-open
for user-space components.

---

## 14. Tray Agent — Background Notification Daemon

`RansomShieldTray.exe` is a Windows-subsystem application (no console window,
`WinMain` entry point) that provides a persistent system-tray icon and balloon
notifications. It uses the same `CommManager`, `ConfigManager`, and
`EventLogger` as the CLI client.

**Single-instance guard**: a named mutex (`Global\RansomShieldTrayMutex_3F7A`)
ensures only one tray instance runs at a time:

```cpp
// TrayMain.cpp (conceptual)
HANDLE hMutex = CreateMutex(NULL, TRUE, L"Global\\RansomShieldTrayMutex_3F7A");
if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(hMutex);
    return 0;  // another instance is running
}
```

The `Global\` prefix makes the mutex visible across all terminal services
sessions (necessary on multi-user systems).

**Message marshaling**: the listener thread calls `FltGetMessage()` which may
block indefinitely. To display UI, the result must be on the main thread (the
Windows message pump thread). The solution is `PostMessage(WM_RSBLOCKED)`: the
listener thread pushes the alert data to a `std::queue` (protected by a mutex),
then posts a custom Windows message to the hidden window. The main thread's
`WndProc` processes this message and calls `Shell_NotifyIcon()` with
`NIM_MODIFY` + `NIIF_WARNING` to show the balloon.

This marshal-via-message-queue pattern is the standard Windows approach for
cross-thread UI updates; direct UI calls from background threads violate the
Win32 threading model [Petzold, 1998, "Programming Windows", Ch. 14].

**Auto-start**: the tray registers itself in
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` so it starts automatically
at user login, without requiring a service registration or UAC elevation.

---

## 15. Security Threat Model

### What RansomShield protects against

- **Mass-encryption ransomware** (WannaCry, CryptoLocker, Ryuk patterns):
  processes that encrypt hundreds of files per minute. Caught within the first
  T seconds of activity.
- **Extension-renaming ransomware**: caught by `IRP_MJ_SET_INFORMATION`
  interception even if the write volume is low.
- **Self-evasion by rate throttling**: impossible against sticky blocks.
- **Delayed attacks**: even a slow ransomware (10 files/minute) will be caught
  after K/rate minutes = 50/10 = 5 minutes.

### What RansomShield does NOT protect against

- **Single-file wiper**: a process that destroys exactly one file is below
  threshold. Protecting against wipers would require content-analysis
  heuristics (entropy measurement, file-type mismatch detection).
- **Ransomware spawning many child processes**: if each child process encrypts
  fewer than K files, none of them trips the threshold. Mitigation: process
  tree tracking (sum children's operations into the parent's context).
- **Kernel-mode ransomware** (rootkit-level): a driver at a lower altitude or
  with direct disk access bypasses the filter stack entirely.
- **Ransomware running as SYSTEM with explicit unblock privileges**: an attacker
  with SYSTEM access can send `RsRequestUnblockPid` directly via the port
  (which requires `SeLoadDriverPrivilege`). This is equivalent to
  administrator-level rootkit access; at that point the system is already
  compromised.

### Communication port security

The port is created with a security descriptor that restricts access to
Administrators and SYSTEM:

```c
// CommPort.c:180
status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
```

`FltBuildDefaultSecurityDescriptor` creates a DACL granting full access to
the LocalSystem account and the Administrators group. Unprivileged processes
cannot connect to the port and therefore cannot unblock PIDs.

Reference: [Russinovich et al., 2017, "Windows Internals Part 2", Ch. 9
"Security"]; [Howard & LeBlanc, 2002, "Writing Secure Code"].

---

## 16. Design Tradeoffs and Limitations

### Memory consumption

Each `RS_PROCESS_CONTEXT` is `256 × 8 + overhead ≈ 2,200` bytes in
non-paged pool. With the cap of 1,024 PIDs:

```
1,024 × 2,200 ≈ 2.2 MB of non-paged pool
```

Non-paged pool on modern 64-bit Windows is limited to approximately 256 MB
(configurable), so 2.2 MB is negligible. The hash table itself (`1,021 ×
sizeof(LIST_ENTRY) = 1,021 × 16 = ~16 KB`) is statically allocated in the
driver's `.data` section.

### Spinlock contention

All file I/O operations from all processes on all volumes funnel through the
same spinlock. At DISPATCH_LEVEL, any other thread on this CPU is prevented from
running. For high-I/O workloads (file servers, database servers), spinlock
contention could become measurable.

Mitigation options (not implemented, to keep the design simple):
- Per-bucket spinlocks: 1,021 spinlocks, each protecting one bucket. Reduces
  contention by the hash table size factor in the average case.
- Read-write spinlock (`KeAcquireSpinLockSharedAtDpcLevel`): allow multiple
  readers to look up contexts concurrently; serialize only writers.

### Monotonically increasing timestamps

`KeQueryInterruptTime()` is monotonically increasing per-CPU but may not be
synchronized across CPUs on NUMA systems before Windows 8. On modern systems,
`KeQueryInterruptTime()` is backed by the High Precision Event Timer (HPET) or
TSC and is globally consistent.

---

## 17. References

**Academic papers**

- Kharraz, A., Arshad, S., Mulliner, C., Robertson, W., & Kirda, E. (2016).
  UNVEIL: A Large-Scale, Automated Approach to Detecting Ransomware. *25th
  USENIX Security Symposium*, 757–772.
  — Empirical study of 1,359 ransomware samples; demonstrates the file-write
  rate signature exploited by RansomShield's heuristic engine.

- Continella, A., Guagnelli, A., Zingaro, G., De Pasquale, G., Barenghi, A.,
  Zanero, S., & Maggi, F. (2016). ShieldFS: A Self-Healing, Ransomware-Aware
  Filesystem. *32nd Annual Conference on Computer Security Applications
  (ACSAC)*, 336–347.
  — Proposes a kernel-level file system filter for ransomware detection; shares
  the sliding-window behavioral approach with RansomShield.

- Saltzer, J. H., & Schroeder, M. D. (1975). The Protection of Information in
  Computer Systems. *Proceedings of the IEEE*, 63(9), 1278–1308.
  — Establishes the "fail-safe defaults" principle applied in the sticky-block
  design.

**Systems books**

- Russinovich, M., Solomon, D., & Ionescu, A. (2017). *Windows Internals,
  Part 1* (7th ed.). Microsoft Press.
  — Authoritative reference on the I/O Manager, IRP model, IRQL, spinlocks,
  non-paged pool, and the Object Manager.

- Oney, W. (2003). *Programming the Microsoft Windows Driver Model* (2nd ed.).
  Microsoft Press.
  — Covers legacy filter drivers; the FltMgr minifilter model supersedes this,
  but the IRP and IRQL chapters remain essential background.

- Knuth, D. E. (1998). *The Art of Computer Programming, Volume 3: Sorting and
  Searching* (2nd ed.). Addison-Wesley.
  — §6.4 covers hash table design including the prime-modulus argument.

- Corbet, J., Rubini, A., & Kroah-Hartman, G. (2005). *Linux Device Drivers*
  (3rd ed.). O'Reilly Media.
  — Linux analogue to Windows kernel programming; spinlock and memory pool
  concepts are directly comparable.

- Petzold, C. (1998). *Programming Windows* (5th ed.). Microsoft Press.
  — Ch. 14 documents the Windows message-pump threading model applied in the
  tray agent's cross-thread notification design.

- Tanenbaum, A. S., & Wetherall, D. J. (2011). *Computer Networks* (5th ed.).
  Prentice Hall.
  — §5.3 covers token bucket and sliding window rate-limiting algorithms,
  the theoretical foundation of the heuristic engine.

**Security engineering**

- Howard, M., & LeBlanc, D. (2002). *Writing Secure Code* (2nd ed.).
  Microsoft Press.
  — Covers secure kernel programming, privilege restriction, and pool safety
  (NX pool predates this edition but the principles apply).

- Schmidt, D. C. (2000). Double-Checked Locking. In *Pattern Languages of
  Program Design 3*. Addison-Wesley.
  — Documents the DCL pattern used in `RsRecordOperation` context creation.

**Microsoft documentation**

- Microsoft. (2024). Allocated filter altitudes.
  https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes

- Microsoft. (2024). FLT_OPERATION_REGISTRATION structure.
  https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/ns-fltkernel-_flt_operation_registration

- Microsoft. (2024). FltCreateCommunicationPort function.
  https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatecommunicationport

- Microsoft. (2024). ExAllocatePool2 function.
  https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2
