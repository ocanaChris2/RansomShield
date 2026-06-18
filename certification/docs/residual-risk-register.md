# RansomShield Driver — Residual Risk Register

Document version 1.0 · 2026-06-07.

Tracks accepted residual risks and open findings, each with severity, rationale,
and disposition. Remediated items (closed during certification) are in §10 of the
[certification report](../RansomShield-Certification-Report.md) (R-01…R-05).

Severity: Low / Medium / High. Disposition: **Accepted** (documented, no action
now) · **Planned** (remediation scheduled) · **Mitigated** (compensating control).

---

| ID | Finding | Severity | Disposition | Rationale & remediation |
|---|---|---|---|---|
| **F-03** | INF is not a Universal INF: legacy `[DefaultInstall]`/`[DefaultUninstall]` model and minifilter service keys (`Altitude`, `SupportedFeatures`, `Instances`, `Flags`) are at the service root rather than under a `Parameters` subkey. Strict `InfVerif /w` reports errors. | Medium | **Planned** | Not required for the current test-signed, locally deployed posture (the deploy script writes service registry keys directly and the driver loads/verifies correctly). **Required before a Microsoft attestation submission.** Concrete corrected INF is provided in the [attestation submission runbook](attestation-submission-runbook.md) §3. |
| **F-04** | Multi-process work-splitting: ransomware spawning N children each under the per-PID threshold may evade detection. | Medium | **Accepted** | Documented design limitation (`LITERATURE.md` §16). Future mitigation: roll child operations into the parent context (process-tree tracking). |
| **F-05** | Spinlock contention: all monitored I/O funnels through one global spinlock; measurable on extreme-I/O servers. | Low | **Accepted / Mitigated** | Critical sections are intentionally tiny (pointer/counter ops). Future option: per-bucket or reader/writer locks (`LITERATURE.md` §16). |
| **F-06** | Single-file wiper / low-volume destruction is below threshold. | Low | **Accepted** | Out of the heuristic's scope by design; would require content/entropy analysis. Stated in the threat model and `LITERATURE.md` §16. |
| **F-07** | Privileged adversary (Administrator/SYSTEM) can unload the driver or issue the unblock command. | Medium | **Accepted** | Explicit trust-model assumption: RansomShield targets pre-escalation ransomware; the control port is already restricted to SYSTEM+Administrators. |
| **F-08** | `RsInstanceSetupCallback` attaches to **all** volume types including network volumes, which can raise false positives from file-server workloads. | Low | **Accepted / Mitigated** | Documented in `kernel/RansomShield.c:559`. Mitigation: allowlist server processes, or skip network volumes in `InstanceSetup` if needed for a given deployment. |
| **F-09** | Diagnostics use `DbgPrint` rather than WPP/ETW tracing. | Low | **Accepted** | No security impact; WPP/ETW is a serviceability enhancement for a future release. |
| **F-10** | BinSkim may flag binary-hardening items not enabled for the kernel build (e.g. CFG/`/guard:cf`). | Low | **Planned** | Reviewed per BinSkim run; driver-N/A rules go in `-KnownExceptions`; genuine hardening gaps (if any) are enabled in the project. |

---

## Acceptance

The above residual risks are accepted for `RansomShield.sys` v1.0.0.0 in its
current posture. **F-03** is the sole item that must be closed before a Microsoft
attestation submission. This register is reviewed at each certification revision.
