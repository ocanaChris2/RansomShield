<#
.SYNOPSIS
    Code Analysis (PREfast) gate for the RansomShield driver.

.DESCRIPTION
    Builds RansomShield.vcxproj with /p:RunCodeAnalysis=true using the
    certification ruleset (certification\rulesets\RansomShield.ruleset), which
    layers RansomShield's memory-safety escalations on top of the WDK recommended
    driver rules.

    System/SDK/WDK headers are excluded from the report via the CAExcludePath
    environment variable so the gate reflects only RansomShield's own code under
    kernel\. Any analysis finding referencing a file under kernel\ fails the gate.

    Evidence written to the evidence dir:
      codeanalysis.build.log            full MSBuild output
      codeanalysis.findings.txt         findings filtered to kernel\
      *.nativecodeanalysis.xml          machine-readable analyzer output (copied)
      CodeAnalysis.result.json          gate result

    Runs anywhere the v145 toolset + restored NuGet packages are present (CI-safe).

.PARAMETER Configuration
    Debug (default) or Release.

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Debug',
    [string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader "Code Analysis (PREfast) — $Configuration"
$EvidenceDir = Resolve-RsEvidenceDir -EvidenceDir $EvidenceDir -Configuration $Configuration

$msbuild = Get-RsMSBuild
if (-not $msbuild) {
    Write-RsFail 'MSBuild not found (need Visual Studio with the v145 toolset).'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeAnalysis' -Status 'Skipped' `
        -Details @{ reason = 'MSBuild not found' } | Out-Null
    exit 2
}
if (-not (Test-Path $RsPackages)) {
    Write-RsFail "NuGet packages not restored ($RsPackages). Run: .\nuget.exe restore RansomShield.sln -PackagesDirectory packages"
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeAnalysis' -Status 'Skipped' `
        -Details @{ reason = 'packages not restored' } | Out-Null
    exit 2
}

# Exclude Microsoft's own headers (WDK/SDK ship inside packages\) from the report.
$env:CAExcludePath = @($RsPackages, $env:CAExcludePath) -join ';'
Write-RsInfo "CAExcludePath seeded with: $RsPackages"

$proj    = Join-Path $RsRepoRoot 'RansomShield.vcxproj'
$logPath = Join-Path $EvidenceDir 'codeanalysis.build.log'

Write-RsInfo 'Running msbuild /t:Rebuild /p:RunCodeAnalysis=true ...'
$out = & $msbuild $proj `
        /p:Configuration=$Configuration /p:Platform=x64 `
        /p:SolutionDir="$RsRepoRoot\" `
        /p:RunCodeAnalysis=true /p:EnableMicrosoftCodeAnalysis=true `
        /t:Rebuild /v:minimal /nologo 2>&1 | Out-String
$buildExit = $LASTEXITCODE
$out | Set-Content -Path $logPath -Encoding UTF8

# Collect findings that reference our own sources only.
$ourFindings = ($out -split "`r?`n") |
    Where-Object { $_ -match '\\kernel\\' -and $_ -match 'warning [A-Z]|error [A-Z]' }
$ourFindings | Set-Content -Path (Join-Path $EvidenceDir 'codeanalysis.findings.txt') -Encoding UTF8

# Copy the machine-readable analyzer XML for the record.
$xml = Get-ChildItem (Join-Path $RsRepoRoot "x64\$Configuration") -Filter '*.nativecodeanalysis.xml' `
        -Recurse -ErrorAction SilentlyContinue
foreach ($f in $xml) { Copy-Item $f.FullName -Destination $EvidenceDir -Force }

$findingCount = @($ourFindings).Count
$pass = ($buildExit -eq 0) -and ($findingCount -eq 0)

$result = Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeAnalysis' `
    -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
    -Details @{
        configuration = $Configuration
        ruleset       = 'certification\rulesets\RansomShield.ruleset'
        buildExitCode = $buildExit
        ownFindings   = $findingCount
    } `
    -Artifacts @('codeanalysis.build.log','codeanalysis.findings.txt')

if (-not $pass) {
    Write-RsWarn "$findingCount finding(s) in kernel\ — see codeanalysis.findings.txt"
    $ourFindings | ForEach-Object { Write-RsInfo $_ }
    exit 1
}
Write-RsOk 'No Code Analysis findings in RansomShield sources.'
exit 0
