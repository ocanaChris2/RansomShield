# RansomShield Driver — Microsoft Attestation Submission Runbook

Document version 1.0 · 2026-06-07.

Step-by-step procedure to obtain a **Microsoft-signed** `RansomShield.sys` via
**attestation signing** (the path for software drivers that do not require full
HLK/WHQL). Attestation produces a driver that loads on Windows 10/11 x64 without
test-signing mode and without HVCI complaints.

> **Prerequisites you must obtain separately (cost/identity):**
> - A **Microsoft Partner Center** account with the **Hardware/Windows Hardware
>   Dev Center** program enabled.
> - An **Extended Validation (EV) code-signing certificate** from a Microsoft-
>   recognized CA, registered to the same legal entity as the Partner Center
>   account, with its private key on the required hardware token/HSM.
>
> These cannot be produced by this repository; the steps below assume you have
> them. Until then, the repo's test-signing path
> ([`Deploy-RansomShield.ps1`](../../Deploy-RansomShield.ps1)) remains the local
> deployment mechanism.

---

## 0. Pre-submission checklist (gate before you start)

Do not begin a submission until **all** are true:

- [ ] `Invoke-AllGates.ps1 -Configuration Release -IncludeSdvDvl` is green
      (Code Analysis, CodeQL, BinSkim, SDV+DVL, InfVerif, packaging).
- [ ] `RansomShield.DVL.xml` was produced on the WDK machine (required attachment).
- [ ] Driver Verifier + functional tests pass on the test VM (see
      [test-plan.md](test-plan.md)).
- [ ] **F-03 is closed**: the INF passes strict `InfVerif /w` (Universal) — see §3.
- [ ] The driver builds **Release x64** and carries the version resource (v1.0.0.0).

---

## 1. Build the release driver

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild RansomShield.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir="$PWD\"
# On the WDK machine, also produce the DVL:
pwsh certification\scripts\Invoke-Sdv-Dvl.ps1 -Configuration Release   # -> RansomShield.DVL.xml
```

## 2. Acquire / register the EV certificate

1. Purchase an EV code-signing certificate; complete the CA's identity vetting.
2. In **Partner Center → Drivers**, register the EV certificate (one-time): sign
   the supplied verification blob and upload, linking the cert to your account.
3. Keep the EV private key on its token/HSM; signing is done via that token.

## 3. Close F-03 — make the INF a Universal INF

Strict `InfVerif /w` currently reports that the minifilter service keys must live
under a **`Parameters`** subkey and that the legacy undecorated install sections
are not allowed. Apply the following to `RansomShield.inf`, then **re-validate on
the test VM that the driver still loads** (FltMgr instance registration is
sensitive to this layout — verify with `fltmc` after install).

**3a. `[Version]`** — already corrected during certification (canonical ClassGuid
+ `PnpLockdown=1`). Confirm:

```ini
[Version]
Signature   = "$Windows NT$"
Class       = "ActivityMonitor"
ClassGuid   = {b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}
Provider    = %ProviderString%
DriverVer   = 01/01/2026,1.0.0.0
CatalogFile = RansomShield.cat
PnpLockdown = 1
```

**3b. Use only architecture-decorated install sections** (remove the undecorated
`[DefaultInstall]` / `[DefaultUninstall]` / `*.Services` sections; keep the
`.NTamd64` (and `.NTarm64` if shipping ARM64) variants).

**3c. Move the minifilter service data under `Parameters`** in the AddService
registration:

```ini
[RansomShield_Service_Registration]
DisplayName    = %RansomShield.ServiceDesc%
ServiceType    = 2              ; FILE_SYSTEM_DRIVER
StartType      = 1             ; SYSTEM_START
ErrorControl   = 1
ServiceBinary  = %12%\RansomShield.sys
LoadOrderGroup = "FSFilter Activity Monitor"
AddReg         = RansomShield_AddRegistry

[RansomShield_AddRegistry]
HKR,"Parameters","SupportedFeatures",0x00010001,0x3
HKR,"Parameters\Instances","DefaultInstance",0x00000000,%DefaultInstance%
HKR,"Parameters\Instances\RansomShield Instance","Altitude",0x00000000,%AltitudeString%
HKR,"Parameters\Instances\RansomShield Instance","Flags",0x00010001,0x0
```

**3d. Re-validate:**

```powershell
pwsh certification\scripts\Invoke-InfVerif.ps1   # universal pass should now be clean
```

> Verification note: confirm on the test VM that `fltmc` still lists RansomShield
> at altitude 325010 after an INF-based install with the new layout. If your
> deployment continues to use `Deploy-RansomShield.ps1` (direct registry writes),
> mirror the `Parameters\Instances` layout there too.

## 4. Produce the signed package with the EV certificate

```powershell
# Substitute the EV cert subject (must match the Partner-Center-registered cert).
pwsh certification\scripts\Invoke-PackageDriver.ps1 -Configuration Release `
     -CertSubject "CN=<your EV cert subject>"
```

This stamps the INF, runs **Inf2Cat** (`/os:10_X64`), and signs the catalog +
driver with the EV cert. Confirm `signtool verify /pa /v RansomShield.cat`
reports a valid chain.

## 5. Assemble the submission package

Place the signed artifacts together and zip into a `.cab`/`.zip` as the
Hardware Dev Center expects:

```
RansomShield.sys      (EV-signed)
RansomShield.inf      (Universal)
RansomShield.cat      (EV-signed catalog)
RansomShield.DVL.xml  (Driver Verification Log)
```

Use the WDK `MakeCab`/`Inf2Cat` flow or Partner Center's packaging guidance.
Attach `RansomShield.DVL.xml` to the submission.

## 6. Submit for attestation signing

1. Partner Center → **Drivers → Submit new hardware**.
2. Upload the package; choose **Attestation signing**.
3. Select the target OS (Windows 10/11 **x64**).
4. Submit. Intake runs InfVerif + signature/DVL checks — a clean pre-submission
   checklist (§0) means it passes.

## 7. Retrieve and deploy

1. Download the **Microsoft-signed** package from Partner Center.
2. Deploy the Microsoft-signed `RansomShield.sys` + `.inf` + `.cat`. It now loads
   on stock Windows 10/11 x64 **without** test-signing mode and is HVCI-compatible.
3. Re-run the [test plan](test-plan.md) functional tests against the
   Microsoft-signed binary to confirm behaviour is unchanged, and record the
   signed binary's SHA-256 on the
   [certificate of conformance](certificate-of-conformance.md).

---

## Notes & scope

- **Attestation vs WHQL/WHCP:** attestation requires no HLK run and does not
  grant the "Certified for Windows" logo or Windows Update distribution. If those
  are needed later, run the HLK filter-driver tests and submit for full
  certification — out of scope for this runbook.
- **Renewal:** re-run §1–§7 on any material change to driver code, INF, or
  toolchain, and re-certify (new certificate of conformance).
