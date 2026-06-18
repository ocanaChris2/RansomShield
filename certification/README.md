# RansomShield — Driver Certification Package

Enterprise-grade security & quality certification for the **RansomShield kernel
minifilter** (`RansomShield.sys`). This package contains the formal certification
documents **and** the tooling that produces the supporting evidence, so every
claim is reproducible.

Start here: **[RansomShield-Certification-Report.md](RansomShield-Certification-Report.md)**
(the master report) and the one-page
**[certificate of conformance](docs/certificate-of-conformance.md)**.

---

## What this certifies

`RansomShield.sys` v1.0.0.0 was built and verified under a controlled, repeatable
process and meets the documented security/quality bar: clean Code Analysis (0
findings), no banned APIs, a documented & framework-mapped threat model, a
reproducible **signed driver package** (`.sys` + `.inf` + `.cat`), and runtime/SDV
gates wired for CI and pre-submission. See the report for scope and current status.

## Contents

```
certification/
  RansomShield-Certification-Report.md   Master report (read this first)
  docs/
    threat-model.md                      STRIDE + CWE threat model
    security-development-lifecycle.md    SDL practices mapped to the code
    compliance-matrix.md                 WHCP + SDL + CWE -> evidence
    test-plan.md                         Static + runtime + functional/FP tests
    residual-risk-register.md            Accepted risks & open findings (F-03..)
    attestation-submission-runbook.md    Partner Center + EV + attestation steps
    certificate-of-conformance.md        One-page signed attestation
  rulesets/RansomShield.ruleset          Driver CA rules + memory-safety escalations
  scripts/                               Gate scripts (see below)
  tools/                                 RansomSim.ps1, Workload-FalsePositive.ps1
  evidence/                              Generated bundles (git-ignored)
```

## Reproduce the evidence

**On a build host** (VS 2025 / v145 + restored NuGet packages):

```powershell
# restore once: .\nuget.exe restore RansomShield.sln -PackagesDirectory packages
pwsh certification\scripts\Invoke-AllGates.ps1 -Configuration Release
```

Produces `certification\evidence\<timestamp>-Release\` with per-gate
`*.result.json`, logs/SARIF, the signed package, `environment.json`, and an
aggregated `gate-report.md` / `gate-report.json`.

**On a WDK machine** (adds SDV + DVL):

```powershell
pwsh certification\scripts\Invoke-AllGates.ps1 -Configuration Release -IncludeSdvDvl
# or just: pwsh certification\scripts\Invoke-Sdv-Dvl.ps1 -Configuration Release
```

**On a dedicated test VM** (driver installed, test-signing on / HVCI off):

```powershell
pwsh certification\scripts\Invoke-DriverVerifier.ps1 -Action enable   # reboot
pwsh certification\tools\RansomSim.ps1 -EvidenceDir <bundle>          # detection
pwsh certification\tools\Workload-FalsePositive.ps1 -EvidenceDir <bundle>  # no FP
pwsh certification\scripts\Invoke-DriverVerifier.ps1 -Action query    # capture
```

## Gates

| Gate | Script | Where it runs |
|---|---|---|
| Code Analysis (PREfast + driver ruleset) | `scripts/Invoke-CodeAnalysis.ps1` | Build host / CI |
| CodeQL (Windows driver suite) | `scripts/Invoke-CodeQL.ps1` | CI (needs network first run) |
| BinSkim (binary hardening) | `scripts/Invoke-BinSkim.ps1` | CI (needs nuget.org) |
| InfVerif (INF validation) | `scripts/Invoke-InfVerif.ps1` | Build host / CI |
| Package + catalog signing | `scripts/Invoke-PackageDriver.ps1` | Build host / CI |
| SDV + DVL | `scripts/Invoke-Sdv-Dvl.ps1` | WDK machine |
| Driver Verifier | `scripts/Invoke-DriverVerifier.ps1` | Test VM |
| Functional efficacy / false positive | `tools/RansomSim.ps1`, `tools/Workload-FalsePositive.ps1` | Test VM |
| Orchestrator | `scripts/Invoke-AllGates.ps1` | aggregates the host-runnable set |

CI runs the host-runnable gates on every push and publishes SARIF + the evidence
bundle: [`.github/workflows/driver-certification.yml`](../.github/workflows/driver-certification.yml).

## Related project docs

- [`README.md`](../README.md) — product overview, build, deploy
- [`LITERATURE.md`](../LITERATURE.md) — technical deep-dive (threat model §15, limitations §16)
- [`RansomShield.Driver.vcxproj`](../RansomShield.Driver.vcxproj) — optional WDK Driver project for SDV/DVL
