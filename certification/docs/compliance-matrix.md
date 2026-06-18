# RansomShield Driver — Compliance Matrix

Document version 1.0 · 2026-06-07. Maps each control to its requirement source,
implementation/evidence, and status. Status legend: **Met** · **Met (CI/VM)** =
verified by a gate that runs in CI or on the test VM/WDK machine · **Partial** =
accepted residual item with a remediation path.

---

## A. Microsoft Windows Hardware Compatibility Program — driver fundamentals & static-tools expectations

| # | Requirement | Implementation / Evidence | Status |
|---|---|---|---|
| A1 | Code Analysis clean with the recommended driver rules | `RansomShield.ruleset` + `Invoke-CodeAnalysis.ps1`; **0 findings** | **Met** |
| A2 | Static Driver Verifier clean | `RansomShield.Driver.vcxproj` + `Invoke-Sdv-Dvl.ps1` (`msbuild /t:sdv`) | **Met (WDK)** |
| A3 | Driver Verification Log (DVL) produced for submission | `Invoke-Sdv-Dvl.ps1` (`/t:dvl`) → `RansomShield.DVL.xml` | **Met (WDK)** |
| A4 | CodeQL analysis with the Windows driver suite | `Invoke-CodeQL.ps1` + `windows_driver_recommended.qls` | **Met (CI)** |
| A5 | No banned APIs | Repo scan; only `Rtl*`/`Ex*` used | **Met** |
| A6 | Runtime stability under Driver Verifier | `Invoke-DriverVerifier.ps1` (standard + DDI + low-resource) | **Met (VM)** |
| A7 | Driver image is Authenticode/catalog signed | `Invoke-PackageDriver.ps1` → signed `.cat` (Valid) | **Met** (test cert; EV for prod) |
| A8 | Version resource present in the binary | `kernel/RansomShield.rc` (VS_VERSION_INFO / VFT_DRV) | **Met** |
| A9 | INF passes InfVerif | `Invoke-InfVerif.ps1`; default **Pass** | **Met** |
| A10 | INF is a Universal INF (for attestation submission) | Service keys under `Parameters`, remove legacy install sections | **Partial — F-03** (runbook) |
| A11 | Spectre-mitigated code generation | `SpectreMitigation=Spectre` in `RansomShield.Driver.vcxproj` | **Met (WDK)** |

## B. Microsoft Security Development Lifecycle

| # | Practice | Evidence | Status |
|---|---|---|---|
| B1 | Threat modeling | [`threat-model.md`](threat-model.md), `LITERATURE.md` §15 | **Met** |
| B2 | Ban dangerous functions | No banned CRT APIs | **Met** |
| B3 | Static analysis (multiple engines) | CA + CodeQL + BinSkim + SDV | **Met / Met (CI)** |
| B4 | Memory zeroing (no info leak) | `ExAllocatePool2` + `RtlZeroMemory` reply buffers | **Met** |
| B5 | Least privilege | Port ACL SYSTEM+Admins, single client | **Met** |
| B6 | Secure/fail-safe defaults | Sticky block; documented fail-open on OOM | **Met** |
| B7 | Supply-chain integrity | Pinned WDK/SDK NuGet; reproducible signed package | **Met** |
| B8 | Binary hardening | BinSkim (`/GS`, DEP/NX, ASLR, CFG review) | **Met (CI)** |

## C. CWE coverage (kernel-relevant defect classes)

| CWE | Control | Evidence | Status |
|---|---|---|---|
| CWE-416 Use After Free | Copy-to-stack before unlock; no over-deref of requestor process | `kernel/RansomShield.c:729`; SDV | **Met** |
| CWE-476 NULL Deref | `_In_opt_` + NULL checks (R-01) | CA C6011/C6387=Error | **Met** |
| CWE-457 Uninitialized | Zeroed pool + replies | `kernel/RsContext.c`, `RsCommPort.c` | **Met** |
| CWE-362 Race | Spinlock + DCL | `kernel/RsContext.c:557`; SDV | **Met** |
| CWE-690 Unchecked return | `NT_SUCCESS`/NULL checks | driver-wide | **Met** |
| CWE-20 Input validation | Port message length/type checks | `kernel/RsCommPort.c` | **Met** |
| CWE-400/789 Resource exhaustion | Bounded tables + sticky block | `kernel/RansomShield.h` | **Met** |
| CWE-676 Dangerous functions | No banned APIs | repo scan | **Met** |

## D. Outstanding items

| ID | Item | Owner | Gate |
|---|---|---|---|
| F-03 | Convert INF to Universal (service keys under `Parameters`; drop legacy `[DefaultInstall]`/`[DefaultUninstall]`) | Dev | `InfVerif /w` clean → A10 |

See [`residual-risk-register.md`](residual-risk-register.md) for full disposition
of F-03 and the accepted functional limitations (F-04…F-07).
