<#
.SYNOPSIS
    False-positive workload — shows normal-cadence file activity is NOT blocked,
    and demonstrates the allowlist mitigation for high-rate legitimate tools.

.DESCRIPTION
    RansomShield's heuristic blocks ANY process exceeding the rate threshold
    (default 50 ops / 10 s), so a legitimate high-throughput tool (backup,
    indexer, build) would be a false positive unless allowlisted. This script
    exercises two scenarios on a TEST VM:

      1. NORMAL cadence (default): writes files at a sub-threshold rate. A correct
         driver must NOT block these — proving everyday activity is unaffected.

      2. -HighRate: bursts above the threshold to show the driver WOULD block an
         un-allowlisted bulk tool. Allowlist the process first to suppress it:
             RansomShieldClient.exe allowlist-add powershell.exe
         (stop the tray agent first so the CLI can use the comm port).

    Operates only inside a throwaway directory under %TEMP%.

.PARAMETER TargetDir
    Working directory. Default: %TEMP%\RansomShield-FPTest.

.PARAMETER Ops
    Number of file operations (default 40).

.PARAMETER HighRate
    Burst above the threshold instead of pacing below it.

.PARAMETER EvidenceDir
    Optional. Writes FalsePositive.result.json for the evidence bundle.

.EXAMPLE
    pwsh certification\tools\Workload-FalsePositive.ps1
    pwsh certification\tools\Workload-FalsePositive.ps1 -HighRate
#>
[CmdletBinding()]
param(
    [string]$TargetDir = (Join-Path $env:TEMP 'RansomShield-FPTest'),
    [int]$Ops = 40,
    [switch]$HighRate,
    [string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Say([string]$m, [string]$c = 'Gray') { Write-Host $m -ForegroundColor $c }

# ── Guardrails (same policy as RansomSim) ────────────────────────────────────
$tempRoot = [IO.Path]::GetFullPath($env:TEMP)
$full     = [IO.Path]::GetFullPath($TargetDir)
if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Say "REFUSING: -TargetDir must be under %TEMP% ($full)." Red; exit 2
}
if ((Test-Path $full) -and @(Get-ChildItem $full -Force -ErrorAction SilentlyContinue).Count -gt 0) {
    Say "REFUSING: $full exists and is not empty." Red; exit 2
}
New-Item -ItemType Directory -Path $full -Force | Out-Null

# Pace so that, in NORMAL mode, no 10-second window exceeds ~30 ops (< 50 threshold).
# 1 op every 350 ms => ~28 ops per 10 s window.
$delayMs = if ($HighRate) { 0 } else { 350 }
$mode    = if ($HighRate) { 'HIGH-RATE burst' } else { 'NORMAL cadence' }
Say "False-positive workload: $mode  ($Ops ops, ${delayMs}ms spacing)" Cyan
Say "Working directory: $full   PID: $PID" Cyan

$blob = New-Object byte[] 2048
(New-Object Random).NextBytes($blob)
$attempted = 0; $succeeded = 0; $blocked = 0

for ($i = 0; $i -lt $Ops; $i++) {
    $path = Join-Path $full ("fp_{0:D4}.dat" -f $i)
    $attempted++
    try { [IO.File]::WriteAllBytes($path, $blob); $succeeded++ }
    catch {
        if ($_.Exception.Message -match 'denied|denegado|0x80070005|UnauthorizedAccess') { $blocked++ }
        else { throw }
    }
    if ($delayMs -gt 0) { Start-Sleep -Milliseconds $delayMs }
}

# In NORMAL mode the success criterion is "no blocks" (no false positive).
$noFalsePositive = (-not $HighRate) -and ($blocked -eq 0)
Say ''
Say "Attempted: $attempted   Succeeded: $succeeded   Blocked: $blocked" Cyan
if (-not $HighRate) {
    if ($noFalsePositive) { Say 'RESULT: normal-cadence activity was NOT blocked (no false positive).' Green }
    else { Say 'RESULT: normal activity WAS blocked — investigate threshold/allowlist tuning.' Red }
} else {
    if ($blocked -gt 0) { Say 'RESULT: high-rate burst was blocked (expected). Allowlist the tool to suppress.' Yellow }
    else { Say 'RESULT: high-rate burst not blocked — driver inactive or process already allowlisted.' Yellow }
}

Get-ChildItem $full -Filter 'fp_*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

if ($EvidenceDir) {
    New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
    $status = if ($HighRate) { 'Manual' } elseif ($noFalsePositive) { 'Pass' } else { 'Fail' }
    $obj = [ordered]@{
        gate='FalsePositive'; status=$status; timestamp=(Get-Date).ToString('o'); machine=$env:COMPUTERNAME
        details=[ordered]@{ mode=$mode; opsAttempted=$attempted; opsSucceeded=$succeeded; opsBlocked=$blocked
            note=$(if ($HighRate){'High-rate contrast run; allowlist mitigation applies'} elseif($noFalsePositive){'No false positive on normal cadence'} else {'Unexpected block on normal cadence'}) }
        artifacts=@()
    }
    ($obj | ConvertTo-Json -Depth 6) | Set-Content (Join-Path $EvidenceDir 'FalsePositive.result.json') -Encoding UTF8
}

if (-not $HighRate -and -not $noFalsePositive) { exit 1 }
exit 0
