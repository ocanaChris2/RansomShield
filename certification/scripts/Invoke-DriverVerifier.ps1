<#
.SYNOPSIS
    Runtime verification gate (Driver Verifier) for RansomShield.sys.

.DESCRIPTION
    Drives Windows Driver Verifier against the loaded RansomShield driver to prove
    runtime memory/IRQL/DDI correctness under stress. Because Driver Verifier
    requires reboots, this is a multi-step, operator-driven flow — run it on a
    dedicated TEST VM (test-signing on, HVCI off, driver installed via
    Deploy-RansomShield.ps1), never on a production machine.

    Workflow:
      -Action enable   Enable standard flags + DDI compliance + low-resource
                       simulation for RansomShield.sys, then reboot.
      (reboot, then run the functional stress: certification\tools\RansomSim.ps1)
      -Action query    Capture verifier state + scan for bugcheck minidumps -> evidence.
      -Action reset     Clear all Verifier settings, then reboot.

    A clean run = the driver is verified, the stress completed, and no new
    crash dumps appeared in %SystemRoot%\Minidump.

    Evidence:
      verifier.query.txt / verifier.settings.txt / minidumps.txt
      DriverVerifier.result.json

.PARAMETER Action
    enable | query | reset (default query).

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.
#>
[CmdletBinding()]
param(
    [ValidateSet('enable','query','reset')][string]$Action = 'query',
    [string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader "Driver Verifier — $Action"

# Must be elevated.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { Write-RsFail 'Run from an elevated (Administrator) prompt.'; exit 2 }

$driver = 'RansomShield.sys'

switch ($Action) {
    'enable' {
        # /standard = special pool, pool tracking, force IRQL checking, etc.
        # 0x800 (DDI compliance checking) + 0x10 (low resources simulation) add
        # FltMgr/IRP DDI and allocation-failure coverage relevant to a minifilter.
        Write-RsInfo 'Enabling Driver Verifier (standard + DDI compliance + low-resource sim) ...'
        & verifier /standard /driver $driver | Out-Null
        & verifier /flags 0x810 /driver $driver | Out-Null
        Write-RsWarn 'REBOOT now, then run certification\tools\RansomSim.ps1, then: this script -Action query'
        exit 0
    }
    'reset' {
        Write-RsInfo 'Clearing all Driver Verifier settings ...'
        & verifier /reset | Out-Null
        Write-RsWarn 'REBOOT to fully clear Verifier.'
        exit 0
    }
    'query' {
        $EvidenceDir = Resolve-RsEvidenceDir -EvidenceDir $EvidenceDir
        (& verifier /query)        2>&1 | Out-String | Set-Content (Join-Path $EvidenceDir 'verifier.query.txt')    -Encoding UTF8
        (& verifier /querysettings)2>&1 | Out-String | Set-Content (Join-Path $EvidenceDir 'verifier.settings.txt') -Encoding UTF8

        $verifyingRs = (Get-Content (Join-Path $EvidenceDir 'verifier.query.txt') -Raw) -match 'RansomShield'

        # Scan for crash dumps created during the verification window.
        $dumpDir = Join-Path $env:SystemRoot 'Minidump'
        $dumps = @()
        if (Test-Path $dumpDir) {
            $dumps = Get-ChildItem $dumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue |
                     Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) }
        }
        ($dumps | Select-Object Name, LastWriteTime, Length | Format-Table -Auto | Out-String) |
            Set-Content (Join-Path $EvidenceDir 'minidumps.txt') -Encoding UTF8

        $pass = $verifyingRs -and ($dumps.Count -eq 0)
        Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'DriverVerifier' `
            -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
            -Details @{
                verifyingRansomShield = [bool]$verifyingRs
                recentMinidumps       = $dumps.Count
                note                  = 'Run -Action enable, reboot, run RansomSim, then -Action query.'
            } `
            -Artifacts @('verifier.query.txt','verifier.settings.txt','minidumps.txt') | Out-Null

        if (-not $verifyingRs) { Write-RsWarn 'RansomShield is not under Verifier — did you run -Action enable + reboot?' }
        if ($dumps.Count -gt 0) { Write-RsFail "$($dumps.Count) recent crash dump(s) found — triage with WinDbg !analyze -v." }
        if (-not $pass) { exit 1 }
        exit 0
    }
}
