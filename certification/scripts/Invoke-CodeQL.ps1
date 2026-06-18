<#
.SYNOPSIS
    CodeQL gate for the RansomShield driver (Windows driver query suite).

.DESCRIPTION
    Builds a CodeQL database by compiling RansomShield.vcxproj under CodeQL
    tracing, then analyzes it with the Windows driver recommended query suite
    (falling back to cpp-security-and-quality if the driver suite is absent) and
    emits SARIF. CodeQL is the modern Microsoft Hardware Dev Center submission
    requirement.

    Bootstrapping (first run; needs network):
      * CodeQL CLI bundle  -> downloaded to certification\.tools\codeql if not on PATH.
      * Windows driver pack -> Microsoft/Windows-Driver-Developer-Supplemental-Tools
                               (windows_driver_recommended.qls) cloned to
                               certification\.tools\windows-drivers if -DriverSuiteRepo
                               is not supplied and git is available.

    Evidence:
      codeql.sarif             analysis result
      codeql.summary.txt       rule/result summary
      CodeQL.result.json       gate result

.PARAMETER Configuration
    Debug or Release (default Release).

.PARAMETER EvidenceDir
    Target evidence directory. A fresh timestamped one is created if omitted.

.PARAMETER DriverSuiteRepo
    Optional path to a local checkout of the Windows driver CodeQL suite.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [string]$EvidenceDir,
    [string]$DriverSuiteRepo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\RsCert.Common.ps1"

Write-RsHeader "CodeQL — RansomShield driver ($Configuration)"
$EvidenceDir = Resolve-RsEvidenceDir -EvidenceDir $EvidenceDir -Configuration $Configuration

$msbuild = Get-RsMSBuild
if (-not $msbuild) {
    Write-RsWarn 'MSBuild not found; recording CodeQL as Skipped.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeQL' -Status 'Skipped' `
        -Details @{ reason = 'MSBuild not found' } | Out-Null
    exit 2
}

# ── Locate / bootstrap the CodeQL CLI ────────────────────────────────────────
$codeqlCmd = Get-Command codeql -ErrorAction SilentlyContinue
$codeql = if ($codeqlCmd) { $codeqlCmd.Source } else { $null }
if (-not $codeql) {
    $cacheRoot = Join-Path $RsCertRoot '.tools\codeql'
    $codeql    = Join-Path $cacheRoot 'codeql\codeql.exe'
    if (-not (Test-Path $codeql)) {
        Write-RsInfo 'Downloading the CodeQL CLI bundle (first run only) ...'
        New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null
        $zip = Join-Path $cacheRoot 'codeql-bundle-win64.tar.gz'
        $url = 'https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-win64.tar.gz'
        try {
            Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
            tar -xzf $zip -C $cacheRoot
        } catch {
            Write-RsWarn "CodeQL bundle download failed: $($_.Exception.Message). Recording as Skipped."
            Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeQL' -Status 'Skipped' `
                -Details @{ reason = 'CodeQL CLI unavailable / download failed' } | Out-Null
            exit 2
        }
    }
}
Write-RsInfo "CodeQL: $codeql"

# ── Resolve the query suite ──────────────────────────────────────────────────
$suite = 'cpp-security-and-quality.qls'   # safe default shipped with the bundle
if (-not $DriverSuiteRepo) {
    $DriverSuiteRepo = Join-Path $RsCertRoot '.tools\windows-drivers'
    if (-not (Test-Path $DriverSuiteRepo) -and (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-RsInfo 'Cloning the Windows driver CodeQL suite ...'
        try {
            & git clone --depth 1 `
                https://github.com/microsoft/Windows-Driver-Developer-Supplemental-Tools.git `
                $DriverSuiteRepo 2>&1 | Out-Null
        } catch { Write-RsWarn "Driver suite clone failed; using $suite." }
    }
}
$driverQls = Get-ChildItem $DriverSuiteRepo -Filter 'windows_driver_recommended.qls' `
              -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($driverQls) { $suite = $driverQls.FullName; Write-RsInfo "Driver suite: $suite" }
else { Write-RsWarn "Windows driver suite not found; using built-in $suite." }

# ── Create the database (traced build) ───────────────────────────────────────
$dbDir = Join-Path $EvidenceDir 'codeql-db'
$buildCmd = '"{0}" "{1}" /p:Configuration={2} /p:Platform=x64 /p:SolutionDir="{3}\" /t:Rebuild /v:minimal /nologo' `
            -f $msbuild, (Join-Path $RsRepoRoot 'RansomShield.vcxproj'), $Configuration, $RsRepoRoot

Write-RsInfo 'Creating CodeQL database (this compiles the driver) ...'
& $codeql database create "$dbDir" --language=cpp --overwrite --command=$buildCmd 2>&1 |
    Tee-Object -FilePath (Join-Path $EvidenceDir 'codeql.create.log') | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dbDir)) {
    Write-RsFail 'CodeQL database creation failed (see codeql.create.log).'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeQL' -Status 'Fail' `
        -Details @{ reason = 'database create failed' } -Artifacts @('codeql.create.log') | Out-Null
    exit 1
}

# ── Analyze ──────────────────────────────────────────────────────────────────
$sarif = Join-Path $EvidenceDir 'codeql.sarif'
& $codeql database analyze "$dbDir" "$suite" `
    --format=sarifv2.1.0 --output="$sarif" --download 2>&1 |
    Tee-Object -FilePath (Join-Path $EvidenceDir 'codeql.analyze.log') | Out-Null

if (-not (Test-Path $sarif)) {
    Write-RsFail 'CodeQL analysis produced no SARIF.'
    Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeQL' -Status 'Fail' `
        -Details @{ reason = 'no SARIF produced' } | Out-Null
    exit 1
}

$doc = Get-Content $sarif -Raw | ConvertFrom-Json
$results = @()
foreach ($run in $doc.runs) { if ($run.results) { $results += $run.results } }
$errors = @($results | Where-Object { $_.level -eq 'error' })
($results | Group-Object ruleId, level | ForEach-Object { "{0,-6} {1}" -f $_.Count, $_.Name }) |
    Set-Content -Path (Join-Path $EvidenceDir 'codeql.summary.txt') -Encoding UTF8

$pass = ($errors.Count -eq 0)
Write-RsGateResult -EvidenceDir $EvidenceDir -Gate 'CodeQL' `
    -Status ($(if ($pass) { 'Pass' } else { 'Fail' })) `
    -Details @{
        suite        = (Split-Path $suite -Leaf)
        totalResults = $results.Count
        errorResults = $errors.Count
    } `
    -Artifacts @('codeql.sarif','codeql.summary.txt') | Out-Null

if (-not $pass) { exit 1 }
exit 0
