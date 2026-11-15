<#
.SYNOPSIS
    Process-churn workload — shows RansomShield's per-process tracking stays
    bounded when many short-lived processes write files.

.DESCRIPTION
    Every process that performs a monitored write gets a tracking context in
    the driver's non-paged pool. The driver releases it when the process exits
    (process-notify callback), with a hard cap of 1024 contexts
    (RS_MAX_TRACKED_PIDS) as a backstop.

    This script starts -Count short-lived child processes one after another.
    Each child writes one small file inside a throwaway directory under %TEMP%,
    deletes it and exits (two monitored operations, far below the threshold).
    The script itself never deletes files in bulk: that would make THIS
    process exceed the threshold and get blocked.

    Expected with a healthy driver:
      * no child fails (none is blocked), and
      * afterwards the driver's "Tracked PIDs" count is close to the number of
        live processes that write files: far below 1024. A count stuck at
        about 1024 means exit cleanup is not running and only the cap is
        holding memory down.

    Read "Tracked PIDs" from the tray icon (right-click -> Status), or pass
    -ClientPath to have this script run 'RansomShieldClient.exe --status'
    before and after and check the count itself (stop the tray agent first:
    the driver accepts one client connection at a time).

    Operates only inside a throwaway directory under %TEMP%. Run on a TEST VM.

.PARAMETER TargetDir
    Working directory. Default: %TEMP%\RansomShield-Churn.

.PARAMETER Count
    Number of child processes (default 3000: more than the 1024 cap, so a
    missing exit cleanup shows up as a count pinned at the cap).

.PARAMETER ClientPath
    Optional path to RansomShieldClient.exe. When given, "Tracked PIDs" is read
    before and after the run and checked against the cap.

.PARAMETER EvidenceDir
    Optional. Writes ProcessChurn.result.json for the evidence bundle.

.EXAMPLE
    pwsh certification\tools\Workload-ProcessChurn.ps1
    pwsh certification\tools\Workload-ProcessChurn.ps1 -ClientPath .\x64\Debug\RansomShieldClient.exe -EvidenceDir C:\evidence
#>
[CmdletBinding()]
param(
    [string]$TargetDir = (Join-Path $env:TEMP 'RansomShield-Churn'),
    [ValidateRange(1, 100000)]
    [int]$Count = 3000,
    [string]$ClientPath,
    [string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Say([string]$m, [string]$c = 'Gray') { Write-Host $m -ForegroundColor $c }

$TrackedPidCap = 1024   # RS_MAX_TRACKED_PIDS in kernel/RansomShield.h

# ── Guardrails (same policy as Workload-FalsePositive) ──────────────────────
$tempRoot = [IO.Path]::GetFullPath($env:TEMP)
$full     = [IO.Path]::GetFullPath($TargetDir)
if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Say "REFUSING: -TargetDir must be under %TEMP% ($full)." Red; exit 2
}
if ((Test-Path $full) -and @(Get-ChildItem $full -Force -ErrorAction SilentlyContinue).Count -gt 0) {
    Say "REFUSING: $full exists and is not empty." Red; exit 2
}
if ($ClientPath -and -not (Test-Path -LiteralPath $ClientPath)) {
    Say "REFUSING: -ClientPath not found ($ClientPath)." Red; exit 2
}
New-Item -ItemType Directory -Path $full -Force | Out-Null

# ── Driver status through the CLI (optional) ────────────────────────────────
function Get-TrackedPids {
    if (-not $ClientPath) { return $null }
    $out = (& $ClientPath --status 2>&1 | Out-String)
    $m = [regex]::Match($out, 'Tracked PIDs:\s+(\d+)')
    if (-not $m.Success) {
        Say "Could not read 'Tracked PIDs' from '$ClientPath --status' (is the tray agent still holding the port?):" Yellow
        Say $out.Trim() DarkGray
        return $null
    }
    return [int]$m.Groups[1].Value
}

Say "Process churn: $Count short-lived writers   (cap: $TrackedPidCap tracked PIDs)" Cyan
Say "Working directory: $full" Cyan

$trackedBefore = Get-TrackedPids
if ($null -ne $trackedBefore) { Say "Tracked PIDs before: $trackedBefore" Cyan }

# ── Churn: each child writes one file, deletes it and exits ─────────────────
# Relative file names in the child's working directory avoid quoting issues
# when %TEMP% contains spaces. If the write is denied, cmd exits non-zero and
# '&&' skips the delete.
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$failed = 0
$sw = [Diagnostics.Stopwatch]::StartNew()
for ($i = 0; $i -lt $Count; $i++) {
    $name = 'churn_{0:D6}.txt' -f $i
    $psi = [Diagnostics.ProcessStartInfo]::new($cmd, "/d /c echo churn>$name&&del $name")
    $psi.WorkingDirectory = $full
    $psi.UseShellExecute  = $false
    $psi.CreateNoWindow   = $true
    $p = [Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { $failed++ }
    $p.Dispose()
    if ((($i + 1) % 500) -eq 0) { Say ("  {0}/{1} processes" -f ($i + 1), $Count) DarkGray }
}
$sw.Stop()

$leftover = @(Get-ChildItem $full -Filter 'churn_*' -ErrorAction SilentlyContinue).Count
$trackedAfter = Get-TrackedPids

Say ''
Say "Children: $Count   failed: $failed   files left behind: $leftover   elapsed: $([int]$sw.Elapsed.TotalSeconds) s" Cyan
if ($null -ne $trackedAfter) { Say "Tracked PIDs after: $trackedAfter" Cyan }

$noFailures = ($failed -eq 0)
$bounded = if ($null -ne $trackedAfter) { $trackedAfter -lt $TrackedPidCap } else { $null }

if (-not $noFailures) {
    Say 'RESULT: some single-write children FAILED (blocked?) — investigate before trusting the count.' Red
} elseif ($bounded -eq $true) {
    Say "RESULT: tracking stayed bounded ($trackedAfter tracked, cap $TrackedPidCap): exit cleanup works." Green
} elseif ($bounded -eq $false) {
    Say "RESULT: $trackedAfter tracked PIDs, at the cap: exit cleanup is NOT releasing contexts." Red
} else {
    Say "RESULT: no failures. Now read 'Tracked PIDs' (tray -> Status): it should be far below $TrackedPidCap." Yellow
}

# The directory is empty unless a child failed; a handful of deletes at most.
Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue

if ($EvidenceDir) {
    New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
    $status = if (-not $noFailures) { 'Fail' } elseif ($bounded -eq $true) { 'Pass' } elseif ($bounded -eq $false) { 'Fail' } else { 'Manual' }
    $obj = [ordered]@{
        gate = 'ProcessChurn'; status = $status; timestamp = (Get-Date).ToString('o'); machine = $env:COMPUTERNAME
        details = [ordered]@{
            children = $Count; failed = $failed; leftoverFiles = $leftover
            trackedPidsBefore = $trackedBefore; trackedPidsAfter = $trackedAfter; trackedPidCap = $TrackedPidCap
            elapsedSeconds = [int]$sw.Elapsed.TotalSeconds
            note = $(if ($status -eq 'Manual') { "Read Tracked PIDs from the tray (Status); expect far below $TrackedPidCap" } else { '' })
        }
        artifacts = @()
    }
    ($obj | ConvertTo-Json -Depth 6) | Set-Content (Join-Path $EvidenceDir 'ProcessChurn.result.json') -Encoding UTF8
    Say "Wrote $(Join-Path $EvidenceDir 'ProcessChurn.result.json')" DarkGray
}

if ((-not $noFailures) -or ($bounded -eq $false)) { exit 1 }
exit 0
