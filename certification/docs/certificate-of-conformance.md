# Certificate of Conformance

<div align="center">

## RansomShield File System Minifilter Driver

**`RansomShield.sys` — Version 1.0.0.0**

</div>

---

This certifies that the software product identified above has been developed and
verified in accordance with the **RansomShield Driver Security & Quality
Certification** ([report v1.0](../RansomShield-Certification-Report.md)) and
conforms to that standard for its stated deployment posture.

| Field | Value |
|---|---|
| **Product** | RansomShield File System Minifilter Driver (`RansomShield.sys`) |
| **Version** | 1.0.0.0 |
| **Certification report** | v1.0, 2026-06-07 |
| **Scope** | Kernel driver + control-port trust boundary |
| **Deployment posture certified** | Test-signed, locally deployed (production attestation gated on F-03) |
| **Build toolchain** | Visual Studio 2025 (MSBuild v18), MSVC v145; WDK/SDK NuGet 10.0.26100.6584 |
| **Analyzed binary SHA-256** | `8889BBB964C09A31CD412DAC4D1646170E82FD4176B85B6EB6A98EF3D4485AA0` |
| **Signed package SHA-256** | `CA6D5CCA87D72263D00CDFFB180A98A7F9D5BB16904750FA38B9D7A25976BD8E` |
| **Issue date** | 2026-06-07 |
| **Valid until** | Next material change to driver code, INF, or toolchain (re-certify) |

> The SHA-256 values above are from the reference build. Each certified build
> records its own values in `environment.json` / `gate-report.md` within the
> evidence bundle; the certified binary must match the analyzed binary hash.

## Gate results (reference run 2026-06-07)

| Gate | Result |
|---|---|
| Code Analysis (PREfast + driver ruleset) | **PASS** — 0 findings |
| Banned-API scan | **PASS** — none |
| INF validation (default) | **PASS** |
| Package + catalog signing | **PASS** — catalog signature Valid |
| CodeQL (Windows driver suite) | Scheduled — CI |
| BinSkim (binary hardening) | Scheduled — CI |
| SDV + DVL | Scheduled — WDK machine |
| Driver Verifier + functional efficacy | Scheduled — test VM |

## Conditions

1. This certificate applies only to the exact binary whose hash matches the
   analyzed-binary SHA-256 recorded for the certified build.
2. Outstanding finding **F-03** (Universal INF) must be closed before any
   Microsoft attestation/WHCP submission.
3. Accepted residual risks are recorded in the
   [residual-risk register](residual-risk-register.md).

---

| Role | Name | Signature | Date |
|---|---|---|---|
| Driver engineering | Christian Ocaña | ________________ | __________ |
| Security review | ____________________ | ________________ | __________ |
| Release approval | ____________________ | ________________ | __________ |

<div align="center">

*Generated as part of the RansomShield certification package.
Regenerate evidence with `certification/scripts/Invoke-AllGates.ps1`.*

</div>
