# RansomShield Driver — Secure Development Lifecycle (SDL) Practices

Document version 1.0 · 2026-06-07. This maps RansomShield's implementation to
Microsoft Security Development Lifecycle practices and is the supporting detail
for §4 of the [certification report](../RansomShield-Certification-Report.md).

Each practice lists the **evidence** (a code location, a gate, or an artifact).

---

## 1. Threat modeling

- A documented, framework-mapped threat model exists ([`threat-model.md`](threat-model.md))
  and a narrative model with academic grounding (`LITERATURE.md` §15).
- Trust boundary explicitly identified (control port) and hardened (admin/SYSTEM
  ACL, single client).

## 2. Use safe functions / ban dangerous ones

- **Zero** banned CRT string/memory functions in driver code. Only `Rtl*`
  (`RtlCopyMemory`, `RtlZeroMemory`, `RtlEqualUnicodeString`) and `Ex*` are used.
- Bounded copies only: image-name copy truncates to `RS_MAX_IMAGE_NAME_LEN` and
  NULL-terminates (`kernel/RsContext.c:495`).
- **Evidence:** repository scan; Code Analysis gate.

## 3. Memory safety

| Practice | Implementation | Evidence |
|---|---|---|
| Non-paged, NX pool for DISPATCH_LEVEL data | `ExAllocatePool2(POOL_FLAG_NON_PAGED, …)` | `kernel/RsContext.c:421` |
| Zero-initialized allocations (no info leak) | `ExAllocatePool2` zero-fills; replies `RtlZeroMemory`'d | `kernel/RsCommPort.c` |
| Pool tagging for leak/diagnostics | tag `'hSsR'` (`RS_POOL_TAG`) | `kernel/RansomShield.h:59` |
| Bounded allocations | `RS_MAX_TRACKED_PIDS`, `RS_MAX_OPERATIONS_PER_PID` | `kernel/RansomShield.h` |
| Use-after-free avoidance | copy-to-stack before unlock; no over-deref of requestor process | `kernel/RansomShield.c:729`, `RsContext.c` |

## 4. Concurrency / IRQL correctness

- Single global spinlock `g_ContextLock`; intentionally short critical sections.
- **Double-checked locking**: allocate at `PASSIVE_LEVEL` (no lock), re-acquire,
  re-check, insert-or-free (`kernel/RsContext.c:557`).
- IRQL-sensitive APIs guarded: `SeLocateProcessImageName` only at
  `PASSIVE_LEVEL`; `FltSendMessage` only after lock release.
- **Evidence:** SDV (rule set for IRQL/locking), Driver Verifier (DDI + force
  IRQL), CA rule C28121 escalated to Error.

## 5. Static analysis (defense in depth)

- MSVC Code Analysis with the WDK recommended driver ruleset + RansomShield
  escalations ([`rulesets/RansomShield.ruleset`](../rulesets/RansomShield.ruleset)).
- CodeQL with the Windows driver recommended suite.
- BinSkim binary-hardening verification.
- Static Driver Verifier + Driver Verification Log.
- **Evidence:** the gate scripts and evidence bundle (§5 of the report).

## 6. Least privilege & secure defaults

| Practice | Implementation |
|---|---|
| Control channel restricted | `FltBuildDefaultSecurityDescriptor` → SYSTEM + Administrators; 1 client |
| Fail-safe (containment) defaults | Detection state is **sticky**; only an admin command unblocks |
| Deliberate availability tradeoff | OOM during tracking is **fail-open**, documented inline (`kernel/RansomShield.c:773`) |
| Avoid destabilizing the system | Paging I/O and System PID (0/4) skipped to prevent bugchecks |

## 7. Supply chain & build integrity

- Pinned, restorable toolchain: NuGet WDK/SDK `10.0.26100.6584`
  (`packages.config`); v145 toolset.
- Reproducible packaging + catalog signing (`Invoke-PackageDriver.ps1`); driver
  carries a version resource for build↔binary correlation.
- `PnpLockdown=1` protects installed driver files from tampering.

## 8. Verification & release gates

- Automated gate orchestrator ([`Invoke-AllGates.ps1`](../scripts/Invoke-AllGates.ps1))
  produces a signed-off evidence bundle; CI runs the host-runnable gates on every
  push (`.github/workflows/driver-certification.yml`).
- Runtime verification on a dedicated test VM (Driver Verifier + functional
  efficacy + false-positive tests) per the [test plan](test-plan.md).

## 9. Response / serviceability

- Real-time block notifications carry PID, image, op count, and timestamp to user
  mode (Event Log + tray balloon).
- Configuration (threshold, allowlist, enable/disable) is adjustable at runtime
  via the admin-only port without reinstalling the driver.
