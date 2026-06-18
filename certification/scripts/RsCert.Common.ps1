<#
.SYNOPSIS
    Shared helpers for the RansomShield certification gate scripts.

.DESCRIPTION
    Dot-source this from each Invoke-*.ps1:

        . "$PSScriptRoot\RsCert.Common.ps1"

    Provides: consistent logging, repo/path discovery, tool location (Windows
    Kits + pinned NuGet packages), evidence-directory management, SHA-256
    hashing, and a uniform per-gate result writer (<gate>.result.json).

    PowerShell 5.1-compatible (matches Deploy-RansomShield.ps1).
#>

Set-StrictMode -Version Latest

# ── Paths ───────────────────────────────────────────────────────────────────
# scripts dir → certification dir → repo root
$script:RsScriptRoot = $PSScriptRoot
$script:RsCertRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:RsRepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:RsPackages   = Join-Path $RsRepoRoot 'packages'
$script:RsWdkVer     = '10.0.26100.6584'

# ── Logging (mirrors Deploy-RansomShield.ps1 conventions) ────────────────────
function Write-RsHeader([string]$m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-RsOk([string]$m)     { Write-Host "  [OK]  $m"   -ForegroundColor Green  }
function Write-RsWarn([string]$m)   { Write-Host "  [!]   $m"   -ForegroundColor Yellow }
function Write-RsFail([string]$m)   { Write-Host "  [ERR] $m"   -ForegroundColor Red    }
function Write-RsInfo([string]$m)   { Write-Host "        $m"   -ForegroundColor DarkGray }

# ── Toolchain discovery ──────────────────────────────────────────────────────
function Get-RsMSBuild {
    # Prefer vswhere; fall back to the pinned VS 2025 path used elsewhere in the repo.
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $hit = & $vswhere -latest -requires Microsoft.Component.MSBuild `
                          -find 'MSBuild\**\Bin\MSBuild.exe' 2>$null |
               Select-Object -First 1
        if ($hit -and (Test-Path $hit)) { return $hit }
    }
    $fallback = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe'
    if (Test-Path $fallback) { return $fallback }
    return $null
}

function Get-RsKitTool {
    <#
      Locate an SDK/WDK tool (signtool.exe, Inf2Cat.exe, InfVerif.exe, stampinf.exe,
      makecat.exe). Searches the installed Windows Kits bin tree (x64 then x86) and
      the pinned NuGet package tool/bin directories. Returns the highest-versioned hit.
    #>
    param([Parameter(Mandatory)][string]$Name)

    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path  $env:ProgramFiles        'Windows Kits\10\bin'),
        (Join-Path  $RsPackages "Microsoft.Windows.WDK.x64.$RsWdkVer\c"),
        (Join-Path  $RsPackages "Microsoft.Windows.SDK.CPP.$RsWdkVer\c\bin")
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($arch in @('x64', 'x86')) {
        foreach ($root in $roots) {
            $hit = Get-ChildItem $root -Filter $Name -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -match "\\$arch\\" } |
                   Sort-Object FullName -Descending |
                   Select-Object -First 1 -ExpandProperty FullName
            if ($hit) { return $hit }
        }
    }
    # Last resort: any architecture.
    foreach ($root in $roots) {
        $hit = Get-ChildItem $root -Filter $Name -Recurse -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
        if ($hit) { return $hit }
    }
    return $null
}

# ── Build artifacts ──────────────────────────────────────────────────────────
function Get-RsDriverBinary {
    param([ValidateSet('Debug','Release')][string]$Configuration = 'Release')
    return (Join-Path $RsRepoRoot "x64\$Configuration\RansomShield.sys")
}

function Get-RsSha256 {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

# ── Evidence directory ───────────────────────────────────────────────────────
function New-RsEvidenceDir {
    <# Creates certification\evidence\<timestamp>\ and records it in LATEST.txt. #>
    param([string]$Configuration = 'Release')
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir   = Join-Path $RsCertRoot "evidence\$stamp-$Configuration"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    # LATEST.txt is a convenience pointer; never let a lock (e.g. OneDrive) abort a run.
    try { Set-Content -Path (Join-Path $RsCertRoot 'evidence\LATEST.txt') -Value $dir -Encoding ASCII -ErrorAction Stop }
    catch { Write-RsWarn "Could not update LATEST.txt: $($_.Exception.Message)" }
    return $dir
}

function Resolve-RsEvidenceDir {
    <# Returns the provided dir, or creates a fresh one if blank. #>
    param([string]$EvidenceDir, [string]$Configuration = 'Release')
    if ($EvidenceDir) {
        New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
        return (Resolve-Path $EvidenceDir).Path
    }
    return (New-RsEvidenceDir -Configuration $Configuration)
}

# ── Per-gate result record ───────────────────────────────────────────────────
function Write-RsGateResult {
    <#
      Writes <Gate>.result.json into the evidence dir and returns the object.
      Status is one of: Pass, Fail, Skipped, Manual.
    #>
    param(
        [Parameter(Mandatory)][string]$EvidenceDir,
        [Parameter(Mandatory)][string]$Gate,
        [Parameter(Mandatory)][ValidateSet('Pass','Fail','Skipped','Manual')][string]$Status,
        [hashtable]$Details = @{},
        [string[]]$Artifacts = @()
    )
    $obj = [ordered]@{
        gate       = $Gate
        status     = $Status
        timestamp  = (Get-Date).ToString('o')
        machine    = $env:COMPUTERNAME
        details    = $Details
        artifacts  = $Artifacts
    }
    $path = Join-Path $EvidenceDir ("{0}.result.json" -f $Gate)
    ($obj | ConvertTo-Json -Depth 6) | Set-Content -Path $path -Encoding UTF8
    switch ($Status) {
        'Pass'    { Write-RsOk   "$Gate : PASS" }
        'Fail'    { Write-RsFail "$Gate : FAIL" }
        'Skipped' { Write-RsWarn "$Gate : SKIPPED" }
        'Manual'  { Write-RsWarn "$Gate : MANUAL (run on the designated machine)" }
    }
    return $obj
}
