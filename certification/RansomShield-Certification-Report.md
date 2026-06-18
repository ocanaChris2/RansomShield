# RansomShield Driver — Security & Quality Certification Report

| | |
|---|---|
| **Product** | RansomShield File System Minifilter Driver (`RansomShield.sys`) |
| **Version** | 1.0.0.0 |
| **Document version** | 1.0 |
| **Issued** | 2026-06-07 |
| **Classification** | Internal / customer-shareable |
| **Prepared by** | RansomShield Development |
| **Status** | **PASS** (host-runnable gates green; runtime/SDV gates scheduled — see §6, §11) |

> This report certifies that `RansomShield.sys` was designed, implemented, and
> verified under a controlled, repeatable process and meets the security and
> quality bar described herein. Every claim is backed by an artifact produced by
> the gate scripts in [`certification/scripts`](scripts) and recorded in a
> timestamped evidence bundle (`certification/evidence/<timestamp>/`). Regenerate
> the evidence at any time with
> [`Invoke-AllGates.ps1`](scripts/Invoke-AllGates.ps1).

---

## 1. Executive summary & scope

RansomShield is a Windows kernel-mode **minifilter** that detects and blocks
ransomware in real time by observing file-system I/O and flagging any process
that exceeds a sliding-window modification-rate threshold. This certification
covers the **kernel driver only** (`RansomShield.sys`); the user-mode CLI and
tray agent are in scope only where they form the driver's trust boundary (the
communication port).

**What was certified**

- The driver builds cleanly and embeds a version resource (v1.0.0.0).
- It passes **Code Analysis** (PREfast) with the WDK recommended driver ruleset
  plus RansomShield memory-safety escalations — **0 findings** in driver code.
- It contains **no banned/unsafe CRT APIs**.
- Its threat model, secure-development practices, and residual risks are
  documented and mapped to recognized frameworks (Microsoft WHCP static-tools
  expectations, Microsoft SDL, and CWE).
- A **signed driver package** (`.sys` + `.inf` + `.cat`) is produced
  reproducibly; the catalog signature validates.
- The static/runtime gates that require a WDK-equipped machine or a test VM
  (SDV + DVL, Driver Verifier, CodeQL, BinSkim) are wired and documented for
  execution in CI and pre-submission (see §6, §11).

**Build provenance (reference run 2026-06-07, machine CHRISTIAN, Windows 11 Pro
10.0.26200)**

| Item | Value |
|---|---|
| Toolchain | Visual Studio 2025 (MSBuild v18), MSVC **v145** |
| Kernel SDK/WDK | NuGet `Microsoft.Windows.WDK.x64` / `…SDK.CPP` **10.0.26100.6584** |
| Analyzed `RansomShield.sys` (Release, unsigned) SHA-256 | `8889BBB964C09A31CD412DAC4D1646170E82FD4176B85B6EB6A98EF3D4485AA0` |
| Signed package `RansomShield.sys` SHA-256 | `CA6D5CCA87D72263D00CDFFB180A98A7F9D5BB16904750FA38B9D7A25976BD8E` |
| Catalog signature | Valid (test cert `CN=RansomShield Test Signing`; substitute EV cert for production) |

*(Hashes are regenerated per build; the live values are recorded in
`environment.json` / `gate-report.md` in the evidence bundle and in the
[certificate of conformance](docs/certificate-of-conformance.md).)*

---

## 2. Product & architecture

RansomShield registers with the Windows Filter Manager (FltMgr) at altitude
**325010** (the Anti-Virus range) and intercepts two I/O operation types:

| IRP | Direction | Purpose |
|---|---|---|
| `IRP_MJ_WRITE` (skips paging I/O) | pre-op | Catch in-place overwrite / encryption |
| `IRP_MJ_SET_INFORMATION` | pre + post | Catch extension renames and deletes |

A per-PID heuristic engine tracks each process's file operations in a sliding
time window (default **50 operations in 10 seconds**). On threshold breach the
PID is flagged, all subsequent write/rename/delete IRPs are completed with
`STATUS_ACCESS_DENIED`, and a notification is pushed to user mode. The block is
**sticky** (cleared only by an authenticated admin command).

Full architecture, data structures, and design rationale are documented in
[`README.md`](../README.md) and the technical deep-dive
[`LITERATURE.md`](../LITERATURE.md); the security analysis builds on
`LITERATURE.md` §15 (threat model) and §16 (limitations) rather than repeating
it. The condensed, framework-mapped model is in
[`docs/threat-model.md`](docs/threat-model.md).

Key trust boundary: the FltMgr communication port `\RansomShieldPort`, created
with `FltBuildDefaultSecurityDescriptor` (`kernel/RsCommPort.c`) granting access
to **SYSTEM and Administrators only**, single client at a time.

---

## 3. Threat model (summary)

The driver's adversary is ransomware running as a **standard or non-elevated
process** attempting mass file destruction. The detailed STRIDE/CWE model is in
[`docs/threat-model.md`](docs/threat-model.md); highlights:

- **Detected/blocked:** mass-encryption bursts; extension-rename ransomware;
  rate-throttling evasion (defeated by the sticky block); slow attackers
  (caught once cumulative ops cross the window threshold).
- **Explicitly out of scope (residual risk, accepted):** single-file wipers;
  multi-process work-splitting; kernel-mode/rootkit attackers below the filter
  altitude; an attacker already holding Administrator/SYSTEM (who can issue the
  unblock command). See [`docs/residual-risk-register.md`](docs/residual-risk-register.md).
- **Trust boundary hardening:** the control port is admin/SYSTEM-only; all
  user→kernel messages are length-validated in `RsMessageNotifyCallback`
  (`kernel/RsCommPort.c`).

---

## 4. Secure development lifecycle

RansomShield's implementation follows the practices detailed in
[`docs/security-development-lifecycle.md`](docs/security-development-lifecycle.md).
Evidence highlights:

- **Memory safety by construction.** All per-PID state is allocated from
  `NonPagedPoolNx` via `ExAllocatePool2` (zero-initialized — prevents pool info
  leaks; NX — HVCI-compatible), tagged `'hSsR'` for Driver Verifier tracking
  (`kernel/RsContext.c:421`).
- **No banned APIs.** The driver uses only `Rtl*`/`Ex*` primitives; a repository
  scan finds **zero** occurrences of `strcpy`/`sprintf`/`wcscpy`/`memcpy`/… in
  driver code.
- **Full SAL annotation.** Every routine is SAL-annotated; the IRQL/aliasing
  contracts are encoded (`_In_`, `_Out_writes_to_`, `_Flt_CompletionContext_Outptr_`).
  A contract defect found during certification (a NULL-tolerant parameter
  annotated `_In_`) was corrected to `_In_opt_` — see §10.
- **Defensive concurrency.** A single global spinlock with short critical
  sections and a double-checked-locking allocation pattern (allocate at
  `PASSIVE_LEVEL`, re-check under lock) prevents both IRQL violations and races
  (`kernel/RsContext.c:557`).
- **Use-after-free avoidance.** Fields needed after releasing the lock are copied
  to stack locals first; `ObDereferenceObject` is deliberately not called on the
  unreferenced `FltGetRequestorProcess()` pointer (`kernel/RansomShield.c:729`).
- **Fail-safe defaults.** Detection state is sticky; OOM during tracking is
  fail-open by explicit, documented choice (`kernel/RansomShield.c:773`).

---

## 5. Static analysis results

| Gate | Tool | Result (reference run) | Evidence |
|---|---|---|---|
| Code Analysis | MSVC PREfast + `RansomShield.ruleset` | **Pass — 0 findings** in `kernel\` | `codeanalysis.build.log`, `*.nativecodeanalysis.xml` |
| Banned APIs | repo scan | **Pass — none** | §4; `LITERATURE.md` |
| INF validation | `InfVerif /v` | **Pass** (default); Universal mode flags F-03 | `infverif.legacy.log`, `infverif.universal.log` |
| CodeQL | CodeQL CLI + `windows_driver_recommended.qls` | Runs in CI / pre-submission | `codeql.sarif` |
| BinSkim | Microsoft BinSkim | Runs in CI (needs nuget.org) | `binskim.sarif` |
| SDV + DVL | `msbuild /t:sdv` + `dvl.exe` | Runs on WDK machine → `RansomShield.DVL.xml` | `sdv.log`, `RansomShield.DVL.xml` |

The Code Analysis ruleset ([`rulesets/RansomShield.ruleset`](rulesets/RansomShield.ruleset))
includes Microsoft's recommended driver rules and **escalates** key
memory-safety rules (C6011 NULL-deref, C6014 leak, C6385/C6386 buffer over/underrun,
C6387 possibly-NULL argument, C28121 wrong-IRQL, C28197 leak, …) to **Error**.
System/SDK/WDK headers are excluded from results via `CAExcludePath` so the gate
reflects only RansomShield code.

---

## 6. Runtime verification

Runtime gates run on a **dedicated test VM** (test-signing on, HVCI off, driver
installed via [`Deploy-RansomShield.ps1`](../Deploy-RansomShield.ps1)):

- **Driver Verifier** ([`Invoke-DriverVerifier.ps1`](scripts/Invoke-DriverVerifier.ps1)):
  standard flags + DDI compliance + low-resource simulation against
  `RansomShield.sys`; a clean run shows the driver verified, the functional
  stress completed, and **no bugcheck minidumps**.
- **Functional efficacy** ([`tools/RansomSim.ps1`](tools/RansomSim.ps1)): a benign
  simulator bursts create→overwrite→rename in a throwaway directory; a healthy
  driver blocks the process mid-burst (Access Denied), proving detection.
- **False-positive behaviour** ([`tools/Workload-FalsePositive.ps1`](tools/Workload-FalsePositive.ps1)):
  normal-cadence activity is **not** blocked; the `-HighRate` contrast run shows
  the allowlist mitigation for legitimate bulk tools.

The procedure and acceptance criteria are in
[`docs/test-plan.md`](docs/test-plan.md).

---

## 7. Compliance

Full control-by-control mapping is in
[`docs/compliance-matrix.md`](docs/compliance-matrix.md), covering:

- **Microsoft Windows Hardware Compatibility Program** static-tools / driver
  fundamentals expectations (Code Analysis, SDV, DVL, CodeQL, no banned APIs,
  proper signing, version resource).
- **Microsoft Security Development Lifecycle** practices.
- **CWE** coverage for the defect classes most relevant to kernel drivers
  (CWE-416, CWE-476, CWE-457, CWE-362, CWE-690, CWE-20, CWE-400, …).

---

## 8. Signing & deployment attestation

The packaging gate ([`Invoke-PackageDriver.ps1`](scripts/Invoke-PackageDriver.ps1))
stages the driver + INF, stamps the INF DriverVer, generates the security
catalog with **Inf2Cat**, and signs the catalog and driver. In the reference run
the catalog signature is **Valid**. The development path uses a self-signed test
certificate; the **production path** (Partner Center + EV certificate +
Microsoft attestation signing) is documented step-by-step in
[`docs/attestation-submission-runbook.md`](docs/attestation-submission-runbook.md).

This certification fixed two long-standing packaging gaps: the INF previously
referenced a `RansomShield.cat` that nothing produced, and the driver carried no
version resource. Both are resolved (see §10).

---

## 9. Known limitations & residual risk

The driver's functional limitations (single-file wiper, multi-process splitting,
kernel-level attackers, spinlock contention under extreme I/O) are analyzed in
`LITERATURE.md` §16 and tracked, with disposition, in
[`docs/residual-risk-register.md`](docs/residual-risk-register.md). The most
material certification-level item is **F-03**: the INF uses the legacy
`[DefaultInstall]` model and is not a Universal INF, so strict `InfVerif /w` and
a Microsoft attestation submission require the INF changes given in the
submission runbook. This is accepted for the current (test-signed, locally
deployed) posture and is a prerequisite for production attestation.

---

## 10. Findings remediated during certification

| ID | Finding | Severity | Resolution |
|---|---|---|---|
| R-01 | `RsRecordOperation`/`RsCreateProcessContext`/`RsCopyImageNameToContext` accepted NULL image names but were annotated `_In_`; Code Analysis C6387 at `RansomShield.c:758,928` | Medium (contract/false-confidence) | Annotations corrected to `_In_opt_`; CA now clean |
| R-02 | INF `ClassGuid` did not match the `ActivityMonitor` class (`…e8c12202e5a6`) | Medium (install integrity) | Corrected to the canonical `{b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}` (verified by InfVerif) |
| R-03 | INF missing `PnpLockdown=1` (InfVerif 1324) | Low | Added to `[Version]` |
| R-04 | `RansomShield.sys` carried no version resource | Low | Added `kernel/RansomShield.rc` (VS_VERSION_INFO, VFT_DRV); embedded v1.0.0.0 |
| R-05 | INF referenced `RansomShield.cat` but no catalog was ever produced/signed | Medium (deployment integrity) | `Invoke-PackageDriver.ps1` generates + signs the catalog |

---

## 11. Certification statement

On the basis of the evidence summarized above and recorded in the evidence
bundle, `RansomShield.sys` v1.0.0.0 **conforms** to the RansomShield Driver
Security & Quality bar for its current deployment posture (test-signed, locally
deployed), with the host-runnable gates green and the machine-restricted gates
(SDV/DVL, Driver Verifier, CodeQL, BinSkim) wired for execution in CI and prior
to any production attestation submission. Outstanding item **F-03** must be
closed before a Microsoft attestation submission.

See the signed one-page
[certificate of conformance](docs/certificate-of-conformance.md).

### Revision history

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-06-07 | Initial certification; remediated R-01…R-05; established gate pipeline and evidence bundle |
