<#
.SYNOPSIS
    Orchestrates the host-runnable RansomShield certification gates and emits the
    aggregated evidence bundle.

.DESCRIPTION
    Creates one timestamped evidence directory and runs the gates that work on a
    normal build host (Code Analysis, InfVerif, BinSkim, CodeQL, driver
    packaging). Each gate runs in an isolated child process so its exit handling
    cannot affect this orchestrator. Results (<gate>.result.json) are aggregated
    into gate-report.json + gate-report.md alongside an environment.json capturing
    the toolchain and the SHA-256 of the analyzed driver.

    Machine-restricted gates are recorded as Manual unless their switch is given:
      -IncludeSdvDvl          run SDV+DVL (requires the WDK + VS driver extension)
      -IncludeDriverVerifier  capture Driver Verifier state (test VM, elevated)

.PARAMETER Configuration
    Debug or Release (default Release — the certification target).

.PARAMETER IncludeSdvDvl
    Also run Invoke-Sdv-Dvl.ps1 (WDK machine only).

.PARAMETER IncludeDriverVerifier
    Also run Invoke-DriverVerifier.ps1 -Action query (test VM, elevated).

.PARAMETER SkipCodeQL
    Skip the CodeQL gate (it can be slow / needs network on first run).

.EXAMPLE
    pwsh certification\scripts\Invoke-AllGates.ps1 -Configuration Release
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [switch]$IncludeSdvDvl,
    [switch]$IncludeDriverVerifier,
    [switch]$SkipCodeQL
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader "RansomShield certification gates — $Configuration"
$EvidenceDir = New-RsEvidenceDir -Configuration $Configuration
Write-RsOk "Evidence directory: $EvidenceDir"

# Same host that is running this script (isolates each gate's `exit`).
$pwshExe = (Get-Process -Id $PID).Path

function Invoke-Gate {
    param([string]$Script, [string[]]$ExtraArgs = @())
    $path = Join-Path $PSScriptRoot $Script
    if (-not (Test-Path $path)) { Write-RsWarn "Missing gate script: $Script"; return 2 }
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $path,
              '-EvidenceDir', $EvidenceDir) + $ExtraArgs
    & $pwshExe @args
    return $LASTEXITCODE
}

# ── Run host-runnable gates ──────────────────────────────────────────────────
Invoke-Gate 'Invoke-CodeAnalysis.ps1' @('-Configuration', $Configuration) | Out-Null
Invoke-Gate 'Invoke-InfVerif.ps1'                                          | Out-Null
Invoke-Gate 'Invoke-BinSkim.ps1'      @('-Configuration', $Configuration)  | Out-Null
if (-not $SkipCodeQL) {
    Invoke-Gate 'Invoke-CodeQL.ps1'   @('-Configuration', $Configuration)  | Out-Null
} else {
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeQL' -Status 'Skipped' `
        -Details @{ reason = '-SkipCodeQL specified' } | Out-Null
}
Invoke-Gate 'Invoke-PackageDriver.ps1' @('-Configuration', $Configuration) | Out-Null

# ── Machine-restricted gates ─────────────────────────────────────────────────
if ($IncludeSdvDvl) {
    Invoke-Gate 'Invoke-Sdv-Dvl.ps1' @('-Configuration', $Configuration) | Out-Null
} else {
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'SdvDvl' -Status 'Manual' `
        -Details @{ reason = 'WDK machine; run Invoke-Sdv-Dvl.ps1 or pass -IncludeSdvDvl' } | Out-Null
}
if ($IncludeDriverVerifier) {
    Invoke-Gate 'Invoke-DriverVerifier.ps1' @('-Action','query') | Out-Null
} else {
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'DriverVerifier' -Status 'Manual' `
        -Details @{ reason = 'Test VM; run Invoke-DriverVerifier.ps1 (enable->reboot->RansomSim->query)' } | Out-Null
}

# ── Environment / provenance ─────────────────────────────────────────────────
$sys = Get-RsDriverBinary -Configuration $Configuration
$msbuild = Get-RsMSBuild
$envInfo = [ordered]@{
    timestamp     = (Get-Date).ToString('o')
    machine       = $env:COMPUTERNAME
    os            = (Get-CimInstance Win32_OperatingSystem).Caption + ' ' + [System.Environment]::OSVersion.Version
    configuration = $Configuration
    msbuild       = $msbuild
    driver        = $sys
    driverSha256  = (Get-RsSha256 $sys)
    driverVersion = $(if (Test-Path $sys) { [Diagnostics.FileVersionInfo]::GetVersionInfo($sys).FileVersion } else { $null })
}
($envInfo | ConvertTo-Json -Depth 5) | Set-Content (Join-Path $EvidenceDir 'environment.json') -Encoding UTF8

# ── Aggregate ────────────────────────────────────────────────────────────────
$results = Get-ChildItem $EvidenceDir -Filter '*.result.json' |
    ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json }

($results | ConvertTo-Json -Depth 8) | Set-Content (Join-Path $EvidenceDir 'gate-report.json') -Encoding UTF8

$rank = @{ 'Fail' = 0; 'Pass' = 1; 'Manual' = 2; 'Skipped' = 3 }
$rows = $results | Sort-Object { $rank[$_.status] }, gate | ForEach-Object {
    $detail = ($_.details.PSObject.Properties |
        ForEach-Object { "$($_.Name)=$($_.Value)" } | Select-Object -First 4) -join '; '
    "| {0} | {1} | {2} |" -f $_.gate, $_.status, $detail
}
$failed = @($results | Where-Object { $_.status -eq 'Fail' })
$overall = $(if ($failed.Count -eq 0) { 'PASS' } else { "FAIL ($($failed.Count) gate(s))" })

$md = @()
$md += "# RansomShield Certification Gate Report"
$md += ""
$md += "- **Generated:** $($envInfo.timestamp)"
$md += "- **Machine:** $($envInfo.machine) — $($envInfo.os)"
$md += "- **Configuration:** $Configuration"
$md += "- **Driver:** ``$([IO.Path]::GetFileName($sys))`` v$($envInfo.driverVersion)"
$md += "- **SHA-256:** ``$($envInfo.driverSha256)``"
$md += "- **Overall:** **$overall**"
$md += ""
$md += "| Gate | Status | Details |"
$md += "|------|--------|---------|"
$md += $rows
$md += ""
$md += "_Status legend: Pass = gate green · Fail = blocking · Manual = run on the designated machine (WDK box / test VM) · Skipped = tool unavailable._"
$md -join "`r`n" | Set-Content (Join-Path $EvidenceDir 'gate-report.md') -Encoding UTF8

Write-RsHeader "Summary"
$results | Sort-Object gate | ForEach-Object { "  {0,-16} {1}" -f $_.gate, $_.status } | Write-Host
Write-Host ""
Write-RsOk "Report: $(Join-Path $EvidenceDir 'gate-report.md')"
if ($failed.Count -gt 0) { Write-RsFail "Overall: $overall"; exit 1 }
Write-RsOk "Overall: PASS"
exit 0
