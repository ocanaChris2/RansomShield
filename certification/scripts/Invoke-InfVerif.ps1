<#
.SYNOPSIS
    INF validation gate (InfVerif) for RansomShield.inf.

.DESCRIPTION
    Runs InfVerif against RansomShield.inf to validate the installation
    descriptor. Two passes are recorded:

      1. Legacy/driver pass  : InfVerif /v RansomShield.inf
      2. Universal pass      : InfVerif /v /w RansomShield.inf   (strict, Universal)

    The Universal pass is EXPECTED to report issues today: RansomShield.inf uses
    the legacy [DefaultInstall]/[DefaultUninstall] + rundll32 setupapi model,
    which is not a Universal INF. That is finding #3 in the residual-risk register;
    resolving it is a prerequisite in the attestation submission runbook. The gate
    therefore PASSES on the legacy pass and records the Universal pass as evidence
    (it does not fail the build on the known Universal gap).

    Evidence:
      infverif.legacy.log / infverif.universal.log
      InfVerif.result.json

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.
#>
[CmdletBinding()]
param([string]$EvidenceDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader 'INF validation (InfVerif)'
$EvidenceDir = Resolve-RsEvidenceDir -EvidenceDir $EvidenceDir

$inf = Join-Path $RsRepoRoot 'RansomShield.inf'
$infverif = Get-RsKitTool -Name 'InfVerif.exe'
if (-not $infverif) {
    Write-RsWarn 'InfVerif.exe not found (Windows SDK/WDK). Recording as Skipped.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'InfVerif' -Status 'Skipped' `
        -Details @{ reason = 'InfVerif.exe not found' } | Out-Null
    exit 2
}
Write-RsInfo "InfVerif: $infverif"

# Pass 1 — default/driver validation.
$legacyLog = Join-Path $EvidenceDir 'infverif.legacy.log'
$legacyOut = (& $infverif /v $inf 2>&1 | Out-String); $legacyExit = $LASTEXITCODE
$legacyOut | Set-Content -Path $legacyLog -Encoding UTF8
Write-RsInfo "Default validation exit code: $legacyExit"

# Pass 2 — strict Universal validation (expected to flag the legacy sections).
$uniLog = Join-Path $EvidenceDir 'infverif.universal.log'
$uniOut = (& $infverif /v /w $inf 2>&1 | Out-String); $uniExit = $LASTEXITCODE
$uniOut | Set-Content -Path $uniLog -Encoding UTF8

$universalClean = ($uniExit -eq 0)
# Gate passes on the default validation; the Universal gap is a tracked finding.
$pass = ($legacyExit -eq 0)

Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'InfVerif' `
    -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
    -Details @{
        legacyExitCode   = $legacyExit
        universalExitCode= $uniExit
        universalClean   = $universalClean
        knownFinding     = 'F-03 legacy INF is not Universal; see residual-risk-register.md'
    } `
    -Artifacts @('infverif.legacy.log','infverif.universal.log') | Out-Null

if (-not $universalClean) {
    Write-RsWarn 'Universal INF validation reported issues (expected — tracked as F-03).'
}
if (-not $pass) { exit 1 }
exit 0
