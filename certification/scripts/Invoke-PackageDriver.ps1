<#
.SYNOPSIS
    Build the signed driver package (.sys + .inf + .cat) — fixes findings F-01/F-02.

.DESCRIPTION
    Stages RansomShield.sys and RansomShield.inf into a clean package directory,
    stamps the INF DriverVer, generates the security catalog with Inf2Cat, and
    signs the catalog (and the .sys) with the test code-signing certificate
    (CN=RansomShield Test Signing — created/reused exactly as Deploy-RansomShield.ps1
    does). The signed catalog is the input the attestation submission needs; the
    repo previously shipped an INF that *referenced* RansomShield.cat but never
    produced one.

    For PRODUCTION attestation the same package is signed with the organisation's
    EV certificate instead (see attestation-submission-runbook.md). This script
    uses the test cert so the gate is reproducible offline.

    Evidence (package\ subfolder):
      RansomShield.sys / .inf / .cat   the signed package
      package.signature.txt            signtool verify output
      PackageDriver.result.json        gate result

.PARAMETER Configuration
    Debug or Release (default Release).

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.

.PARAMETER CertSubject
    Code-signing certificate subject. Defaults to the repo's test cert.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [string]$EvidenceDir,
    [string]$CertSubject = 'CN=RansomShield Test Signing'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader "Driver packaging + catalog signing ($Configuration)"
$EvidenceDir = Resolve-RsEvidenceDir -EvidenceDir $EvidenceDir -Configuration $Configuration

$sys = Get-RsDriverBinary -Configuration $Configuration
$inf = Join-Path $RsRepoRoot 'RansomShield.inf'
if (-not (Test-Path $sys)) {
    Write-RsFail "Driver binary not found: $sys"
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'PackageDriver' -Status 'Skipped' `
        -Details @{ reason = 'driver binary missing' } | Out-Null
    exit 2
}

$stampinf = Get-RsKitTool -Name 'stampinf.exe'
$inf2cat  = Get-RsKitTool -Name 'Inf2Cat.exe'
$signtool = Get-RsKitTool -Name 'signtool.exe'
if (-not $inf2cat -or -not $signtool) {
    Write-RsWarn 'Inf2Cat.exe and/or signtool.exe not found (Windows SDK/WDK). Recording as Skipped.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'PackageDriver' -Status 'Skipped' `
        -Details @{ reason = 'Inf2Cat/signtool not found' } | Out-Null
    exit 2
}

# ── Stage the package ────────────────────────────────────────────────────────
$pkg = Join-Path $EvidenceDir 'package'
New-Item -ItemType Directory -Path $pkg -Force | Out-Null
Copy-Item $sys -Destination $pkg -Force
Copy-Item $inf -Destination $pkg -Force
$stagedInf = Join-Path $pkg 'RansomShield.inf'
$stagedCat = Join-Path $pkg 'RansomShield.cat'

# ── Stamp DriverVer (date = today, version = the one in RansomShield.inf) ────
# The INF is the version's source of truth here; Set-RsVersion.ps1 keeps it in
# step with kernel\RansomShield.rc (the release workflow runs it from the tag).
$infText = Get-Content -Path $inf -Raw
if ($infText -match '(?m)^DriverVer\s*=\s*[0-9/]+,(\d+\.\d+\.\d+\.\d+)') {
    $driverVersion = $Matches[1]
} else {
    Write-RsFail 'Could not read the DriverVer version from RansomShield.inf.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'PackageDriver' -Status 'Fail' `
        -Details @{ reason = 'DriverVer not found in RansomShield.inf' } | Out-Null
    exit 1
}
if ($stampinf) {
    & $stampinf -f $stagedInf -d * -v $driverVersion -a amd64 2>&1 | Out-Null
    Write-RsInfo "INF DriverVer stamped ($driverVersion)."
}

# ── Generate the catalog ─────────────────────────────────────────────────────
Write-RsInfo 'Running Inf2Cat (/os:10_X64) ...'
$catLog = & $inf2cat /driver:"$pkg" /os:10_X64 /verbose 2>&1 | Out-String
$catLog | Set-Content -Path (Join-Path $EvidenceDir 'inf2cat.log') -Encoding UTF8
if (-not (Test-Path $stagedCat)) {
    Write-RsFail 'Inf2Cat did not produce RansomShield.cat (see inf2cat.log).'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'PackageDriver' -Status 'Fail' `
        -Details @{ reason = 'Inf2Cat failed' } -Artifacts @('inf2cat.log') | Out-Null
    exit 1
}

# ── Obtain the test signing certificate (reuse, else create) ─────────────────
$cert = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $CertSubject -and $_.HasPrivateKey } |
        Select-Object -First 1
if (-not $cert) {
    Write-RsInfo "Creating self-signed code-signing cert ($CertSubject) ..."
    $cert = New-SelfSignedCertificate -Subject $CertSubject `
        -CertStoreLocation 'Cert:\CurrentUser\My' -Type CodeSigningCert `
        -HashAlgorithm SHA256 -KeyUsage DigitalSignature -KeyLength 2048
}

# ── Sign catalog + driver ────────────────────────────────────────────────────
foreach ($target in @($stagedCat, (Join-Path $pkg 'RansomShield.sys'))) {
    & $signtool sign /v /s My /sha1 $cert.Thumbprint /fd sha256 "$target" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-RsFail "signtool failed for $target"
        Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'PackageDriver' -Status 'Fail' `
            -Details @{ reason = "signtool failed: $target" } | Out-Null
        exit 1
    }
}

$verify = & $signtool verify /v /pa "$stagedCat" 2>&1 | Out-String
$verify | Set-Content -Path (Join-Path $EvidenceDir 'package.signature.txt') -Encoding UTF8
$catSig = Get-AuthenticodeSignature $stagedCat
$pass = ($catSig.Status -eq 'Valid')
if (-not $pass) {
    Write-RsFail "Catalog signature: $($catSig.Status). $($catSig.StatusMessage)"
    Write-RsInfo 'An untrusted root means this machine does not trust the test certificate.'
    Write-RsInfo 'Deploy-RansomShield.ps1 trusts it (LocalMachine\Root and TrustedPublisher); CI does the same before the gates.'
}

Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'PackageDriver' `
    -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
    -Details @{
        catalog        = 'RansomShield.cat'
        catalogStatus  = "$($catSig.Status)"
        catalogMessage = "$($catSig.StatusMessage)"
        signer         = "$($catSig.SignerCertificate.Subject)"
        sysSha256      = (Get-RsSha256 (Join-Path $pkg 'RansomShield.sys'))
        note           = 'Test cert used; substitute the EV cert for production attestation.'
    } `
    -Artifacts @('package\RansomShield.cat','package\RansomShield.sys','package\RansomShield.inf','package.signature.txt') | Out-Null

if (-not $pass) { exit 1 }
Write-RsOk "Signed package ready: $pkg"
exit 0
