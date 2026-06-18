<#
.SYNOPSIS
    Binary-hardening gate (BinSkim) for RansomShield.sys.

.DESCRIPTION
    Runs Microsoft BinSkim against the built driver to verify binary security
    properties (stack protection, /DYNAMICBASE, /NXCOMPAT, signed/strong-name
    where applicable, etc.) and emits SARIF.

    BinSkim is installed on demand as a dotnet tool into certification\.tools\
    if it is not already on PATH (first run needs the .NET SDK + network).

    Some BinSkim rules do not apply to kernel-mode drivers (e.g. user-mode-only
    checks); those are listed in -KnownExceptions and recorded — not failed.
    Any other error-level result fails the gate.

    Evidence:
      binskim.sarif            full SARIF result
      binskim.summary.txt      human-readable rule/result summary
      BinSkim.result.json      gate result

.PARAMETER Configuration
    Debug or Release (default). Release is the certification target.

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.

.PARAMETER KnownExceptions
    BinSkim rule IDs that are not applicable to a kernel driver and should not
    fail the gate (still recorded in evidence). See residual-risk-register.md.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [string]$EvidenceDir,
    [string[]]$KnownExceptions = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader "BinSkim — RansomShield.sys ($Configuration)"
$EvidenceDir = Resolve-RsEvidenceDir -EvidenceDir $EvidenceDir -Configuration $Configuration

$sys = Get-RsDriverBinary -Configuration $Configuration
if (-not (Test-Path $sys)) {
    Write-RsFail "Driver binary not found: $sys (build it first)."
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' -Status 'Skipped' `
        -Details @{ reason = 'driver binary missing' } | Out-Null
    exit 2
}

# Locate or install BinSkim.
$binskimCmd = Get-Command binskim -ErrorAction SilentlyContinue
$binskim = if ($binskimCmd) { $binskimCmd.Source } else { $null }
if (-not $binskim) {
    $toolDir = Join-Path $RsCertRoot '.tools\binskim'
    $binskim = Join-Path $toolDir 'binskim.exe'
    if (-not (Test-Path $binskim)) {
        if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
            Write-RsWarn 'Neither binskim nor the .NET SDK is available. Recording as Skipped.'
            Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' -Status 'Skipped' `
                -Details @{ reason = 'binskim and dotnet not available' } | Out-Null
            exit 2
        }
        Write-RsInfo 'Installing Microsoft.CodeAnalysis.BinSkim (dotnet tool) ...'
        New-Item -ItemType Directory -Path $toolDir -Force | Out-Null
        # Use a clean config (nuget.org only) so a machine-local NuGet.config that
        # shadows the tool package (common in enterprise build envs) is bypassed.
        $nugetCfg = Join-Path $toolDir 'nuget.config'
        @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
'@ | Set-Content -Path $nugetCfg -Encoding UTF8
        try {
            & dotnet tool install Microsoft.CodeAnalysis.BinSkim --tool-path $toolDir --configfile $nugetCfg 2>&1 | Out-Null
        } catch { Write-RsInfo "dotnet tool install raised: $($_.Exception.Message)" }
        if (-not (Test-Path $binskim)) {
            Write-RsWarn 'BinSkim install failed (offline or restricted NuGet source). Recording as Skipped.'
            Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' -Status 'Skipped' `
                -Details @{ reason = 'binskim install failed (no nuget.org access)' } | Out-Null
            exit 2
        }
    }
}
Write-RsInfo "BinSkim: $binskim"

$sarif = Join-Path $EvidenceDir 'binskim.sarif'
& $binskim analyze "$sys" --output "$sarif" --force --pretty-print | Out-Null

if (-not (Test-Path $sarif)) {
    Write-RsFail 'BinSkim produced no SARIF output.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' -Status 'Fail' `
        -Details @{ reason = 'no SARIF produced' } | Out-Null
    exit 1
}

# Parse SARIF for error-level results.
$doc     = Get-Content $sarif -Raw | ConvertFrom-Json
$results = @()
foreach ($run in $doc.runs) { if ($run.results) { $results += $run.results } }
$errors   = @($results | Where-Object { $_.level -eq 'error' })
$blocking = @($errors  | Where-Object { $KnownExceptions -notcontains $_.ruleId })

# Human summary.
$summary = $results | Group-Object ruleId, level |
    ForEach-Object { "{0,-10} {1}" -f $_.Count, $_.Name }
$summary | Set-Content -Path (Join-Path $EvidenceDir 'binskim.summary.txt') -Encoding UTF8

$pass = ($blocking.Count -eq 0)
Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' `
    -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
    -Details @{
        binary          = (Split-Path $sys -Leaf)
        sha256          = (Get-RsSha256 $sys)
        totalResults    = $results.Count
        errorResults    = $errors.Count
        knownExceptions = $KnownExceptions
        blockingErrors  = $blocking.Count
    } `
    -Artifacts @('binskim.sarif','binskim.summary.txt') | Out-Null

if (-not $pass) {
    $blocking | ForEach-Object { Write-RsInfo ("{0}: {1}" -f $_.ruleId, $_.message.text) }
    exit 1
}
exit 0
