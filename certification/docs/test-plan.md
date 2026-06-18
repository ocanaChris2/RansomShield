# RansomShield Driver — Certification Test Plan

Document version 1.0 · 2026-06-07.

Defines the static, runtime, functional, and false-positive tests that constitute
the certification evidence, with environments and acceptance criteria. All gates
write machine-readable results into the evidence bundle
(`certification/evidence/<timestamp>/`).

---

## 1. Environments

| Env | Purpose | Requirements |
|---|---|---|
| **Build host / CI** | Static gates | VS 2025 (v145), restored NuGet WDK/SDK; CodeQL/BinSkim need nuget.org/network |
| **WDK machine** | SDV + DVL + driver Code Analysis | WDK 10.0.26100 + the "Windows Driver Kit" VS extension |
| **Test VM** | Runtime + functional | Win10/11 x64, test-signing **on**, HVCI **off**, driver installed via `Deploy-RansomShield.ps1`; **no real data** |

> The test VM is throwaway. The functional simulator only ever touches files it
> creates inside a `%TEMP%` subdirectory.

---

## 2. Static tests

| ID | Test | Command | Acceptance |
|---|---|---|---|
| T-CA | Code Analysis | `Invoke-CodeAnalysis.ps1 -Configuration Release` | 0 findings in `kernel\`; exit 0 |
| T-QL | CodeQL (driver suite) | `Invoke-CodeQL.ps1 -Configuration Release` | 0 error-level results |
| T-BS | BinSkim hardening | `Invoke-BinSkim.ps1 -Configuration Release` | 0 blocking error results (driver-N/A rules in `-KnownExceptions`) |
| T-INF | INF validation | `Invoke-InfVerif.ps1` | default validation passes; Universal gap tracked (F-03) |
| T-SDV | Static Driver Verifier + DVL | `Invoke-Sdv-Dvl.ps1 -Configuration Release` | SDV defect-free; `RansomShield.DVL.xml` produced |
| T-PKG | Package + catalog signing | `Invoke-PackageDriver.ps1 -Configuration Release` | catalog signature **Valid** |

One-shot host run: `Invoke-AllGates.ps1 -Configuration Release` (add
`-IncludeSdvDvl` on the WDK machine). Output: `gate-report.md` / `gate-report.json`
/ `environment.json`.

---

## 3. Runtime tests (test VM)

### T-DV — Driver Verifier
1. `Invoke-DriverVerifier.ps1 -Action enable` (standard + DDI compliance + low-resource simulation) → **reboot**.
2. Run the functional tests (T-FUNC) to drive load.
3. `Invoke-DriverVerifier.ps1 -Action query` → capture state + scan for minidumps.
4. `Invoke-DriverVerifier.ps1 -Action reset` → reboot to clear.

**Acceptance:** RansomShield is listed as verified; **no new bugcheck minidumps**
in `%SystemRoot%\Minidump`; functional tests still pass.

---

## 4. Functional / efficacy tests (test VM, driver loaded)

### T-FUNC-1 — Detection of a mass-modification burst
- **Run:** `tools/RansomSim.ps1 -FileCount 80 -EvidenceDir <bundle>`
- **Expected:** the process is blocked mid-burst; `opsBlocked > 0`;
  `firstBlockOp` near the configured threshold (default 50). Result `Pass`.

### T-FUNC-2 — Extension-rename detection
- **Run:** RansomSim performs marker renames (`*.rsim_locked`); with `IRP_MJ_SET_INFORMATION`
  monitoring, rename ops contribute to the count and are blocked once flagged.
- **Expected:** rename operations blocked after the PID is flagged.

### T-FP-1 — No false positive on normal cadence
- **Run:** `tools/Workload-FalsePositive.ps1 -Ops 40`
- **Expected:** sub-threshold activity is **not** blocked; `opsBlocked = 0`. Result `Pass`.

### T-FP-2 — Allowlist mitigation for legitimate bulk tools (contrast)
- **Run:** `Workload-FalsePositive.ps1 -HighRate` (shows it *would* block), then
  allowlist the process (`RansomShieldClient.exe allowlist-add powershell.exe`,
  with the tray agent stopped) and re-run.
- **Expected:** un-allowlisted high-rate burst is blocked; after allowlisting it
  is not.

---

## 5. Acceptance summary

A build is **certification-ready** when:

- All static gates (T-CA, T-QL, T-BS, T-SDV, T-PKG) are green and T-INF default
  passes;
- T-DV shows no bugchecks;
- T-FUNC-1/2 confirm detection and T-FP-1 confirms no false positive on normal
  activity;
- the only open finding is a documented, accepted residual item (currently
  **F-03**, required only for production attestation).

Reference run (2026-06-07): T-CA **Pass**, T-INF **Pass**, T-PKG **Pass**;
T-QL/T-BS/T-SDV scheduled for CI/WDK; T-DV/T-FUNC/T-FP scheduled for the test VM.
