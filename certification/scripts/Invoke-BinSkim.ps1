<#
.SYNOPSIS
    Binary-hardening gate (BinSkim) for RansomShield.sys.

.DESCRIPTION
    Runs Microsoft BinSkim against the built driver to verify binary security
    properties (stack protection, /DYNAMICBASE, /NXCOMPAT, signed/strong-name
    where applicable, etc.) and emits SARIF.

    If BinSkim is not on PATH, the pinned version (-BinSkimVersion) is
    installed on demand from nuget.org into certification\.tools\binskim
    (first run needs nuget.exe and network). Microsoft.CodeAnalysis.BinSkim is
    a plain NuGet package, not a dotnet tool: it carries a self-contained
    BinSkim.exe under tools\win-x64.

    Some BinSkim rules do not apply to kernel-mode drivers (e.g. user-mode-only
    checks); those are listed in -KnownExceptions and recorded — not failed.
    Any other error-level result fails the gate.

    Evidence:
      binskim.sarif            full SARIF result
      binskim.summary.txt      human-readable rule/result summary
      binskim.analyze.log      BinSkim console output
      binskim.install.log      NuGet output (only when BinSkim was installed)
      BinSkim.result.json      gate result

.PARAMETER Configuration
    Debug or Release (default). Release is the certification target.

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.

.PARAMETER KnownExceptions
    BinSkim rule IDs that are not applicable to a kernel driver and should not
    fail the gate (still recorded in evidence). See residual-risk-register.md.

.PARAMETER BinSkimVersion
    Microsoft.CodeAnalysis.BinSkim version to install when BinSkim is not on PATH.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [string]$EvidenceDir,
    [string[]]$KnownExceptions = @(),
    [string]$BinSkimVersion = '4.4.9.14'
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

# Locate or install BinSkim. Microsoft.CodeAnalysis.BinSkim is a plain NuGet
# package (not a dotnet tool) with a self-contained build in tools\win-x64.
$binskimCmd = Get-Command binskim -ErrorAction SilentlyContinue
$binskim = if ($binskimCmd) { $binskimCmd.Source } else { $null }
if (-not $binskim) {
    $toolDir = Join-Path $RsCertRoot '.tools\binskim'
    $binskim = Join-Path $toolDir "Microsoft.CodeAnalysis.BinSkim.$BinSkimVersion\tools\win-x64\BinSkim.exe"
    if (-not (Test-Path $binskim)) {
        $nuget = $null
        $nugetCmd = Get-Command nuget -ErrorAction SilentlyContinue
        if ($nugetCmd) { $nuget = $nugetCmd.Source }
        elseif (Test-Path (Join-Path $RsRepoRoot 'nuget.exe')) { $nuget = Join-Path $RsRepoRoot 'nuget.exe' }
        if (-not $nuget) {
            Write-RsWarn 'Neither binskim nor nuget.exe is available. Recording as Skipped.'
            Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' -Status 'Skipped' `
                -Details @{ reason = 'binskim and nuget.exe not available' } | Out-Null
            exit 2
        }
        Write-RsInfo "Installing Microsoft.CodeAnalysis.BinSkim $BinSkimVersion from nuget.org ..."
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
        $installLog = Join-Path $EvidenceDir 'binskim.install.log'
        try {
            & $nuget install Microsoft.CodeAnalysis.BinSkim -Version $BinSkimVersion `
                -OutputDirectory $toolDir -ConfigFile $nugetCfg -NonInteractive 2>&1 |
                Out-File -FilePath $installLog -Encoding utf8
        } catch { "nuget install raised: $($_.Exception.Message)" | Add-Content -Path $installLog }
        if (-not (Test-Path $binskim)) {
            Write-RsWarn 'BinSkim install failed (see binskim.install.log). Recording as Skipped.'
            Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' -Status 'Skipped' `
                -Details @{ reason = 'binskim install failed (see binskim.install.log)' } `
                -Artifacts @('binskim.install.log') | Out-Null
            exit 2
        }
    }
}
Write-RsInfo "BinSkim: $binskim"

# BinSkim 4.x takes --output for the SARIF log (this version has no
# --pretty-print option). Its results carry message templates (an id plus
# arguments) instead of text, which GitHub code scanning does not accept
# ("expected a result message"); the evidence keeps the log exactly as BinSkim
# wrote it. A stale log is removed first so BinSkim never has to overwrite one,
# and its console output is kept.
$sarif      = Join-Path $EvidenceDir 'binskim.sarif'
$analyzeLog = Join-Path $EvidenceDir 'binskim.analyze.log'
Remove-Item -LiteralPath $sarif -ErrorAction SilentlyContinue
try {
    & $binskim analyze "$sys" --output "$sarif" 2>&1 | Out-File -FilePath $analyzeLog -Encoding utf8
} catch { "binskim raised: $($_.Exception.Message)" | Add-Content -Path $analyzeLog }
$binskimExit = $LASTEXITCODE

if (-not (Test-Path $sarif)) {
    Write-RsFail "BinSkim produced no SARIF output (exit $binskimExit, see binskim.analyze.log)."
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' -Status 'Fail' `
        -Details @{ reason = 'no SARIF produced'; exitCode = $binskimExit } `
        -Artifacts @('binskim.analyze.log') | Out-Null
    exit 1
}

# Error-level results (effective level, see Get-RsSarifResults).
$results  = Get-RsSarifResults -Path $sarif
$errors   = @($results | Where-Object { $_.Level -eq 'error' })
$blocking = @($errors  | Where-Object { $KnownExceptions -notcontains $_.RuleId })

# An analysis BinSkim could not complete fails the gate too: without a PDB,
# for example, it reports ERR997 and skips every rule that needs one.
$toolProblems = Get-RsSarifToolProblems -Path $sarif   # already an array; @() would nest it

# Human summary.
$summary = $results | Group-Object RuleId, Level |
    ForEach-Object { "{0,-10} {1}" -f $_.Count, $_.Name }
$summary | Set-Content -Path (Join-Path $EvidenceDir 'binskim.summary.txt') -Encoding UTF8

$pass = ($blocking.Count -eq 0 -and $toolProblems.Count -eq 0)
Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'BinSkim' `
    -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
    -Details @{
        binary          = (Split-Path $sys -Leaf)
        sha256          = (Get-RsSha256 $sys)
        totalResults    = $results.Count
        errorResults    = $errors.Count
        knownExceptions = $KnownExceptions
        blockingErrors  = $blocking.Count
        incomplete      = $toolProblems
        exitCode        = $binskimExit
        tool            = $binskim
    } `
    -Artifacts @('binskim.sarif','binskim.summary.txt','binskim.analyze.log') | Out-Null

if (-not $pass) {
    $toolProblems | ForEach-Object { Write-RsInfo "BinSkim did not complete the analysis: $_" }
    $blocking | ForEach-Object { Write-RsInfo ("{0}: {1}" -f $_.RuleId, $_.Message) }
    exit 1
}
exit 0
