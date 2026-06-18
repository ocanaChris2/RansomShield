<#
.SYNOPSIS
    Static Driver Verifier (SDV) + Driver Verification Log (DVL) gate.

.DESCRIPTION
    Runs against RansomShield.Driver.vcxproj (the optional WDK "Driver" project),
    which is the only configuration that supports the WDK SDV/DVL build targets —
    the default NuGet RansomShield.vcxproj is a DynamicLibrary and cannot.

    Steps:
      1. Code Analysis on the Driver project (loads the C28xxx driver rules).
      2. SDV clean + full check   (msbuild /t:sdv).
      3. DVL generation           (msbuild /t:dvl)  -> RansomShield.DVL.xml.

    REQUIRES (build machine only):
      * Windows Driver Kit + the "Windows Driver Kit" Visual Studio extension
        (not just the NuGet headers/libs). Without it, ConfigurationType=Driver
        cannot build; the gate then records Manual with guidance.

    Evidence:
      sdv.log / dvl.log
      RansomShield.DVL.xml      the submission artifact
      SdvDvl.result.json        gate result

.PARAMETER Configuration
    Release (default) or Debug. Release is the certification target.

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader "Static Driver Verifier + DVL ($Configuration)"
$EvidenceDir = Resolve-RsEvidenceDir -EvidenceDir $EvidenceDir -Configuration $Configuration

$proj = Join-Path $RsRepoRoot 'RansomShield.Driver.vcxproj'
$msbuild = Get-RsMSBuild
if (-not $msbuild -or -not (Test-Path $proj)) {
    Write-RsWarn 'MSBuild or RansomShield.Driver.vcxproj missing; recording as Skipped.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'SdvDvl' -Status 'Skipped' `
        -Details @{ reason = 'msbuild or driver project missing' } | Out-Null
    exit 2
}

function Invoke-Step([string]$Label, [string[]]$Args, [string]$Log) {
    Write-RsInfo "$Label ..."
    $o = & $msbuild $proj /p:Configuration=$Configuration /p:Platform=x64 `
            /p:SolutionDir="$RsRepoRoot\" @Args /v:minimal /nologo 2>&1 | Out-String
    $o | Set-Content -Path (Join-Path $EvidenceDir $Log) -Encoding UTF8
    return $LASTEXITCODE
}

# A trial build verifies the WDK Driver toolchain is actually installed.
$probe = Invoke-Step 'Probing WDK Driver build' @('/t:Build') 'driver.build.log'
if ($probe -ne 0) {
    Write-RsWarn 'Could not build the WDK Driver project — the WDK + VS driver extension is likely not installed.'
    Write-RsInfo  'Install the WDK for 10.0.26100 (VS "Windows Driver Kit" extension), then re-run on that machine.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'SdvDvl' -Status 'Manual' `
        -Details @{ reason = 'WDK Driver toolchain not available'; remediation = 'Install WDK + VS driver extension' } `
        -Artifacts @('driver.build.log') | Out-Null
    exit 3
}

Invoke-Step 'Code Analysis (driver rules)' @('/p:RunCodeAnalysis=true') 'driver.ca.log' | Out-Null
Invoke-Step 'SDV clean'                    @('/t:sdv','/p:Inputs=/clean')          'sdv.clean.log' | Out-Null
$sdvExit = Invoke-Step 'SDV check'         @('/t:sdv','/p:Inputs=/check:default.sdv') 'sdv.log'
$dvlExit = Invoke-Step 'DVL generation'    @('/t:dvl')                               'dvl.log'

$dvl = Get-ChildItem $RsRepoRoot -Filter 'RansomShield.DVL.xml' -Recurse -ErrorAction SilentlyContinue |
       Select-Object -First 1
if ($dvl) { Copy-Item $dvl.FullName -Destination $EvidenceDir -Force }

$pass = ($sdvExit -eq 0) -and ($dvlExit -eq 0) -and $dvl
Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'SdvDvl' `
    -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
    -Details @{
        sdvExitCode = $sdvExit
        dvlExitCode = $dvlExit
        dvlProduced = [bool]$dvl
    } `
    -Artifacts @('sdv.log','dvl.log','RansomShield.DVL.xml') | Out-Null

if (-not $pass) { exit 1 }
exit 0
