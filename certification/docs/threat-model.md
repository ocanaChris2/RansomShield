# RansomShield Driver — Threat Model

**Scope:** `RansomShield.sys` (kernel minifilter) and its trust boundary (the
FltMgr control port). Document version 1.0 · 2026-06-07.

This is the framework-mapped, certification-grade model. It builds on the
narrative analysis in [`LITERATURE.md` §15](../../LITERATURE.md) and is
cross-referenced by the [residual-risk register](residual-risk-register.md).

---

## 1. Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | User files on monitored volumes | The thing ransomware destroys; the protection target |
| A2 | The detection/blocking decision (per-PID state) | If corrupted, protection fails open or false-positives |
| A3 | Driver configuration (threshold, allowlist, enabled) | Tampering disables or weakens detection |
| A4 | The control channel `\RansomShieldPort` | Issues unblock/config commands; a privilege boundary |
| A5 | Kernel integrity / system stability | A driver defect = BSOD or privilege escalation |

## 2. Trust boundaries & entry points

| Boundary | Entry point | Untrusted input |
|---|---|---|
| User process → kernel I/O path | `RsPreOperationWrite`, `RsPreOperationSetInformation` (`kernel/RansomShield.c`) | IRP parameters, requestor PID/image |
| User mode → kernel control | `RsMessageNotifyCallback` (`kernel/RsCommPort.c`) | Message buffers (type, size, payload) |
| Kernel → user notifications | `FltSendMessage` (`kernel/RsCommPort.c`) | (outbound; bounded fixed struct) |

The control port is created with `FltBuildDefaultSecurityDescriptor(&sd,
FLT_PORT_ALL_ACCESS)` → **SYSTEM + Administrators only**, `MaxConnections = 1`.

## 3. Adversary model & assumptions

- **Primary adversary:** ransomware running at **standard/medium integrity**,
  attempting mass file modification.
- **Assumption:** the platform (FltMgr, NTFS, kernel) is trusted; Secure Boot /
  HVCI and code-signing protect the driver image.
- **Assumption:** an attacker with **Administrator or SYSTEM** is out of scope
  for *prevention* — at that point they can unload drivers or issue the unblock
  command; RansomShield aims to detect/contain pre-escalation ransomware.

## 4. STRIDE analysis

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| **S**poofing | Process forges identity to evade tracking | PID taken from `FltGetRequestorProcessId()` (true requestor, impersonation-safe), not the current thread | Multi-process splitting → F-04 |
| **T**ampering | Modify per-PID state / config / driver file | State in non-paged kernel pool under spinlock; config via admin-only port; `PnpLockdown=1` protects installed files | Admin attacker (accepted) |
| **R**epudiation | Deny having performed the burst | Block + `FltSendMessage` notification with PID, image, op count, timestamp; user-mode Event Log | Logging is best-effort on OOM |
| **I**nformation disclosure | Leak kernel memory to user | Replies zero-initialized (`RtlZeroMemory`) before fill; allocations zeroed by `ExAllocatePool2`; fixed-size copies | — |
| **D**enial of service | Crash kernel / exhaust pool / starve CPU | Bounded tracking (`RS_MAX_TRACKED_PIDS`, `RS_MAX_OPERATIONS_PER_PID`); short critical sections; paging-I/O & PID 0/4 skipped; fail-open on OOM | Spinlock contention under extreme I/O → F-05 |
| **E**levation of privilege | Exploit driver to run code in kernel | No banned APIs; full SAL; CA/SDV/DVL/Driver Verifier gates; NX pool; bounds-checked message handlers | Mitigated by gate pipeline |

## 5. Attack-surface inventory (untrusted-input handlers)

| Handler | Untrusted input | Validation |
|---|---|---|
| `RsPreOperationWrite` | IRP flags, requestor | Skips paging I/O & PID 0/4; NULL-safe image handling; fail-open on tracking error (`kernel/RansomShield.c`) |
| `RsPreOperationSetInformation` | `FileInformationClass`, requestor | Switch-filters to rename/delete classes only |
| `RsMessageNotifyCallback` | `InputBuffer`, `InputBufferLength`, `OutputBufferLength` | Length checks before dereferencing the header and per-type payloads; bounded reply sizes (`kernel/RsCommPort.c`) |

## 6. CWE coverage

| CWE | Class | Mitigation in RansomShield |
|---|---|---|
| CWE-416 | Use After Free | Copy fields to stack before releasing `g_ContextLock`; never `ObDereferenceObject` the unreferenced `FltGetRequestorProcess()` pointer |
| CWE-476 | NULL deref | `_In_opt_` contracts + explicit NULL checks (R-01 fix); CA C6011/C6387 = Error |
| CWE-457 | Uninitialized memory | `ExAllocatePool2` zero-fill; replies `RtlZeroMemory`'d |
| CWE-362 | Race condition | Single spinlock + double-checked-locking allocation |
| CWE-690 | Unchecked return → NULL | `NT_SUCCESS` checks; allocation NULL checks |
| CWE-20 | Improper input validation | Port message length/type validation |
| CWE-400 / CWE-789 | Uncontrolled resource consumption | Bounded PID table + per-PID ring buffer; sticky block stops runaway processing |
| CWE-822 | Untrusted pointer deref | Only kernel-provided structures dereferenced; user buffers length-checked |
| CWE-676 | Dangerous functions | No banned CRT APIs used |

## 7. Out-of-scope threats (accepted residual risk)

Single-file wipers (below threshold), multi-process work-splitting,
kernel-mode/rootkit adversaries below the filter altitude, and an attacker who
already holds Administrator/SYSTEM. Rationale and disposition:
[`residual-risk-register.md`](residual-risk-register.md) (F-04…F-07) and
`LITERATURE.md` §16.
