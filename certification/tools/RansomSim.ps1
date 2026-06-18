<#
.SYNOPSIS
    BENIGN ransomware behaviour simulator — proves RansomShield blocks a mass
    file-modification burst. FOR USE ON A DEDICATED TEST VM ONLY.

.DESCRIPTION
    Reproduces the destructive file-system signature of ransomware (rapid
    create -> overwrite -> rename-with-marker-extension) entirely inside a
    throwaway directory, with NO encryption and NO access to real user data.
    When RansomShield is active, the per-PID heuristic (default 50 ops / 10 s)
    flags this process and subsequent operations fail with Access Denied; this
    script counts those blocks as proof of detection.

    SAFETY GUARDRAILS
      * Operates only inside a dedicated working directory under %TEMP%
        (override with -TargetDir, but a path outside %TEMP% requires -Force).
      * Refuses to touch an existing non-empty directory it did not create.
      * Touches only files it creates (named rsim_*.dat / *.rsim_locked).

    This is a security TEST tool. Do not run it on a production machine or any
    machine holding data you care about.

.PARAMETER TargetDir
    Working directory. Default: %TEMP%\RansomShield-RansomSim.

.PARAMETER FileCount
    Number of files to create and then "encrypt" (default 80; > the 50 default
    threshold so a healthy driver trips well within the window).

.PARAMETER EvidenceDir
    Optional. Writes RansomSim.result.json here for the evidence bundle.

.PARAMETER Force
    Permit a -TargetDir outside %TEMP% (still must be empty / self-created).

.EXAMPLE
    pwsh certification\tools\RansomSim.ps1
    pwsh certification\tools\RansomSim.ps1 -FileCount 120 -EvidenceDir C:\evidence
#>
[CmdletBinding()]
param(
    [string]$TargetDir = (Join-Path $env:TEMP 'RansomShield-RansomSim'),
    [int]$FileCount = 80,
    [string]$EvidenceDir,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Say([string]$m, [string]$c = 'Gray') { Write-Host $m -ForegroundColor $c }

Say ''
Say '############################################################' Yellow
Say '#  RansomShield  -  BENIGN ransomware simulator (TEST)     #' Yellow
Say '#  Creates/renames throwaway files only. No encryption.    #' Yellow
Say '#  Run on a dedicated TEST VM only.                        #' Yellow
Say '############################################################' Yellow

# ── Guardrails ───────────────────────────────────────────────────────────────
$tempRoot = [IO.Path]::GetFullPath($env:TEMP)
$full     = [IO.Path]::GetFullPath($TargetDir)
$underTemp = $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)

if (-not $underTemp -and -not $Force) {
    Say "REFUSING: -TargetDir is outside %TEMP% ($full). Re-run with -Force if you are certain." Red
    exit 2
}
# Never operate at a drive root or a known profile/system folder.
$forbidden = @($env:SystemRoot, $env:USERPROFILE, "$env:SystemDrive\") |
    ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
if ($forbidden -contains $full.TrimEnd('\')) {
    Say "REFUSING: -TargetDir resolves to a protected location ($full)." Red
    exit 2
}
if ((Test-Path $full) -and @(Get-ChildItem $full -Force -ErrorAction SilentlyContinue).Count -gt 0) {
    Say "REFUSING: $full exists and is not empty. Use a fresh throwaway directory." Red
    exit 2
}

New-Item -ItemType Directory -Path $full -Force | Out-Null
Say "Working directory: $full" Cyan
Say "Process Id (PID): $PID    Files: $FileCount" Cyan

# ── Burst: create -> overwrite -> rename, as fast as possible ────────────────
$blob = New-Object byte[] 4096
(New-Object Random).NextBytes($blob)

$attempted = 0; $succeeded = 0; $blocked = 0; $firstBlockOp = $null
$sw = [System.Diagnostics.Stopwatch]::StartNew()

function Try-Op([scriptblock]$op) {
    $script:attempted++
    try { & $op; $script:succeeded++; return $true }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'denied|denegado|0x80070005|UnauthorizedAccess') {
            $script:blocked++
            if ($null -eq $script:firstBlockOp) { $script:firstBlockOp = $script:attempted }
            return $false
        }
        throw   # an unexpected error is a real failure
    }
}

for ($i = 0; $i -lt $FileCount; $i++) {
    $path = Join-Path $full ("rsim_{0:D4}.dat" -f $i)
    Try-Op { [IO.File]::WriteAllBytes($path, $blob) }              | Out-Null  # create / write
    Try-Op { [IO.File]::WriteAllBytes($path, $blob) }              | Out-Null  # overwrite ("encrypt")
    Try-Op { Rename-Item -LiteralPath $path -NewName ("rsim_{0:D4}.rsim_locked" -f $i) -ErrorAction Stop } | Out-Null  # marker rename
}
$sw.Stop()

# ── Report ───────────────────────────────────────────────────────────────────
$detected = $blocked -gt 0
Say ''
Say "Operations attempted : $attempted"  Cyan
Say "  succeeded          : $succeeded"
Say "  BLOCKED            : $blocked" ($(if ($detected) {'Green'} else {'Yellow'}))
if ($detected) { Say "First block at operation #$firstBlockOp (elapsed $([int]$sw.Elapsed.TotalMilliseconds) ms)" Green }
Say ''
if ($detected) {
    Say 'RESULT: RansomShield DETECTED and BLOCKED the simulated ransomware burst.' Green
} else {
    Say 'RESULT: No operations were blocked. Either the driver is not loaded/active' Yellow
    Say '        or the threshold was not reached. Verify with: fltmc' Yellow
}

# Best-effort cleanup of our throwaway files.
Get-ChildItem $full -Filter 'rsim_*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

if ($EvidenceDir) {
    New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
    $status = if ($detected) { 'Pass' } else { 'Skipped' }
    $obj = [ordered]@{
        gate = 'RansomSim'; status = $status; timestamp = (Get-Date).ToString('o'); machine = $env:COMPUTERNAME
        details = [ordered]@{
            pid = $PID; targetDir = $full; filesRequested = $FileCount
            opsAttempted = $attempted; opsSucceeded = $succeeded; opsBlocked = $blocked
            firstBlockOp = $firstBlockOp; elapsedMs = [int]$sw.Elapsed.TotalMilliseconds
            note = $(if ($detected) { 'Detection confirmed' } else { 'Driver inactive or threshold not reached' })
        }
        artifacts = @()
    }
    ($obj | ConvertTo-Json -Depth 6) | Set-Content (Join-Path $EvidenceDir 'RansomSim.result.json') -Encoding UTF8
    Say "Wrote $(Join-Path $EvidenceDir 'RansomSim.result.json')" DarkGray
}

if ($detected) { exit 0 } else { exit 1 }
