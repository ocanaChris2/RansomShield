#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploys and installs the RansomShield minifilter driver.

.DESCRIPTION
    Builds (optionally), copies, installs, and loads the RansomShield.sys
    minifilter driver. Requires test signing mode and an admin PowerShell session.

.PARAMETER Configuration
    Build configuration: Debug (default) or Release.

.PARAMETER Action
    install  - Build (if needed), install, and load the driver (default).
    uninstall - Stop, unload, and remove the driver.
    status   - Show current driver status.
    build    - Build only, do not install.

.PARAMETER SkipBuild
    Skip the MSBuild step and use whatever .sys is already in the output dir.

.EXAMPLE
    .\Deploy-RansomShield.ps1
    .\Deploy-RansomShield.ps1 -Configuration Release
    .\Deploy-RansomShield.ps1 -Action uninstall
    .\Deploy-RansomShield.ps1 -Action status
    .\Deploy-RansomShield.ps1 -SkipBuild
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('install', 'uninstall', 'status', 'build')]
    [string]$Action = 'install',

    [switch]$SkipBuild,
    [switch]$SkipSign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Constants ────────────────────────────────────────────────────────────────
$DriverName   = 'RansomShield'
$DriverAlt    = '325010'
$SysFile      = "$DriverName.sys"
$InfFile      = "$DriverName.inf"
$RepoRoot     = $PSScriptRoot
$OutDir       = Join-Path $RepoRoot "x64\$Configuration"
$SysSource    = Join-Path $OutDir $SysFile
$InfSource    = Join-Path $RepoRoot $InfFile
$MSBuild      = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe'
$SolutionDir  = "$RepoRoot\"

# ─── Helpers ──────────────────────────────────────────────────────────────────
function Write-Header([string]$msg) {
    Write-Host "`n=== $msg ===" -ForegroundColor Cyan
}

function Write-Ok([string]$msg)   { Write-Host "  [OK]  $msg" -ForegroundColor Green  }
function Write-Warn([string]$msg) { Write-Host "  [!]   $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "  [ERR] $msg" -ForegroundColor Red    }

function Assert-TestSigningEnabled {
    $bcdedit = bcdedit /enum '{current}' 2>&1
    $tsLine  = $bcdedit | Where-Object { $_ -match 'testsigning' }
    if ($tsLine -match 'Yes') { return }

    Write-Fail 'Test signing is NOT enabled.'
    Write-Host @'

  To enable test signing, run the following from an elevated prompt,
  then reboot before re-running this script:

      bcdedit /set testsigning on
'@ -ForegroundColor Yellow
    exit 1
}

function Assert-HvciDisabled {
    $hvciKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    $val = (Get-ItemProperty $hvciKey -Name Enabled -ErrorAction SilentlyContinue)
    if ($val -and $val.Enabled -eq 1) {
        Write-Fail 'Memory Integrity (HVCI) is ENABLED — it blocks all test-signed drivers regardless of bcdedit test-signing mode.'
        Write-Host @'

  To load test-signed kernel drivers you must disable Memory Integrity first:
    1. Open Windows Security
    2. Device Security → Core isolation → Memory integrity → turn OFF
    3. Reboot
    4. Re-run this script
'@ -ForegroundColor Yellow
        exit 1
    }
    Write-Ok 'Memory Integrity (HVCI) is off — test-signed driver loading is allowed.'
}

function Show-CodeIntegrityLog {
    Write-Host "`n  Last Code Integrity events (most recent first):" -ForegroundColor Yellow
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 6 `
            -ErrorAction Stop |
        ForEach-Object { Write-Host "    $($_.TimeCreated)  Id=$($_.Id)  $($_.Message -replace '\s+',' ')" }
    } catch {
        Write-Warn "Could not read CodeIntegrity/Operational log: $_"
    }
}

function Get-SignTool {
    # Search both Program Files paths for the highest-versioned x64 signtool
    foreach ($root in @('C:\Program Files (x86)\Windows Kits\10\bin',
                         'C:\Program Files\Windows Kits\10\bin')) {
        if (-not (Test-Path $root)) { continue }
        $hit = Get-ChildItem $root -Filter 'signtool.exe' -Recurse -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match '\\x64\\' } |
               Sort-Object FullName -Descending |
               Select-Object -First 1 -ExpandProperty FullName
        if ($hit) { return $hit }
    }
    return $null
}

function Invoke-Sign {
    Write-Header "Signing driver (test certificate)"

    $certSubject = 'CN=RansomShield Test Signing'
    $cert = Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $certSubject -and $_.HasPrivateKey } |
            Select-Object -First 1

    if (-not $cert) {
        Write-Host '  Creating self-signed test code-signing certificate...'
        $cert = New-SelfSignedCertificate `
            -Subject $certSubject `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Type CodeSigningCert `
            -HashAlgorithm SHA256 `
            -KeyUsage DigitalSignature `
            -KeyLength 2048
        Write-Ok "Certificate created  thumbprint=$($cert.Thumbprint)"
    } else {
        Write-Ok "Reusing existing certificate  thumbprint=$($cert.Thumbprint)"
    }

    # Trust the cert machine-wide so the kernel loader accepts it in test-signing mode
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                     $storeName, 'LocalMachine')
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        if (-not ($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
            $store.Add($cert)
            Write-Ok "Added to LocalMachine\$storeName"
        }
        $store.Close()
    }

    $signtool = Get-SignTool
    if (-not $signtool) {
        Write-Fail 'signtool.exe not found under Windows Kits. Install the Windows SDK, or re-run with -SkipSign if you manage signing separately.'
        exit 1
    }
    Write-Host "  signtool: $signtool"

    & $signtool sign /v /s My /sha1 $cert.Thumbprint /fd sha256 $SysSource
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "signtool failed (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }

    $sig = Get-AuthenticodeSignature $SysSource
    if ($sig.Status -ne 'Valid') {
        Write-Fail "Post-sign verification: status=$($sig.Status)  $($sig.StatusMessage)"
        exit 1
    }
    Write-Ok "Driver signed and verified  signer=$($sig.SignerCertificate.Subject)"
}

function Get-DriverStatus {
    $fltmc = fltmc 2>&1 | Where-Object { $_ -match $DriverName }
    return $fltmc
}

function Show-Status {
    Write-Header 'Driver status'
    $status = Get-DriverStatus
    if ($status) {
        Write-Ok "Driver is loaded:`n$status"
    } else {
        Write-Warn "Driver '$DriverName' is NOT currently loaded."
    }

    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Ok "Service status: $($svc.Status)"
    } else {
        Write-Warn 'Service is not registered.'
    }
}

# ─── Build ────────────────────────────────────────────────────────────────────
function Invoke-Build {
    Write-Header "Building $DriverName ($Configuration x64)"

    if (-not (Test-Path $MSBuild)) {
        Write-Fail "MSBuild not found at:`n  $MSBuild"
        Write-Host '  Update the $MSBuild variable in this script to match your VS install.' -ForegroundColor Yellow
        exit 1
    }

    $vcxproj = Join-Path $RepoRoot "$DriverName.vcxproj"
    if (-not (Test-Path $vcxproj)) {
        Write-Fail "$DriverName.vcxproj not found in repo root."
        exit 1
    }

    & $MSBuild $vcxproj `
        /p:Configuration=$Configuration `
        /p:Platform=x64 `
        /p:"SolutionDir=$SolutionDir" `
        /v:minimal `
        /nologo

    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Build failed (exit $LASTEXITCODE)."
        exit $LASTEXITCODE
    }

    Write-Ok "Build succeeded → $SysSource"
}

# ─── Install ──────────────────────────────────────────────────────────────────
function Invoke-Install {
    Write-Header 'Installing driver'

    # Validate artifacts
    if (-not (Test-Path $SysSource)) {
        Write-Fail "Driver binary not found: $SysSource"
        Write-Host "  Run without -SkipBuild, or build manually first." -ForegroundColor Yellow
        exit 1
    }
    if (-not (Test-Path $InfSource)) {
        Write-Fail "INF file not found: $InfSource"
        exit 1
    }

    # ── Step 1: stop + unload any running instance ────────────────────────────
    # Kill user-mode client first so comm port handles are released.
    Get-Process -Name 'RansomShieldClient' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400

    $svcState   = (sc.exe query $DriverName 2>&1) -join ' '
    $filterLoaded = Get-DriverStatus   # non-empty → filter is in fltmc list

    # Detect "stuck" state: SCM says RUNNING but FltMgr has no record of the filter.
    # This happens when RsUnloadCallback ran (FltUnregisterFilter succeeded) but the
    # driver image is still referenced in kernel memory.  Only a reboot can clear it.
    if ($svcState -match 'RUNNING' -and -not $filterLoaded) {
        Write-Fail 'Driver is in a stuck state: service RUNNING but filter not in fltmc.'
        Write-Host @'

  The kernel still holds a reference to the driver image from a previous load.
  This cannot be resolved without a reboot.

  Please reboot, then re-run this script — the driver will NOT auto-start on
  boot (DEMAND_START), so the install will succeed on the next run.
'@ -ForegroundColor Yellow
        exit 1
    }

    if ($filterLoaded) {
        Write-Warn 'Driver loaded — unloading before reinstall.'
        fltmc unload $DriverName 2>&1 | Out-Null
        sc.exe stop   $DriverName 2>&1 | Out-Null
        Start-Sleep -Seconds 1
    }

    # ── Step 2: copy the signed binary ────────────────────────────────────────
    $sysInstalled = "$env:SystemRoot\system32\drivers\$SysFile"
    Copy-Item $SysSource -Destination $sysInstalled -Force
    Write-Ok "Copied $SysFile → $sysInstalled"

    # Verify signature on the installed copy
    $installedSig = Get-AuthenticodeSignature $sysInstalled
    if ($installedSig.Status -ne 'Valid') {
        Write-Fail "Installed file signature invalid: $($installedSig.Status)"
        exit 1
    }
    Write-Ok "Installed file signature valid  signer=$($installedSig.SignerCertificate.Subject)"

    # ── Step 3: write service registry entries directly ───────────────────────
    # Using the registry directly avoids the sc.exe pending-deletion race that
    # causes fltmc load to fail with ERROR_SERVICE_ALREADY_RUNNING (0x80070420)
    # when the driver image is still referenced by the kernel.
    $svcPath    = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverName"
    $instPath   = "$svcPath\Instances"
    $defInstPath= "$instPath\$DriverName"

    New-Item -Path $svcPath    -Force | Out-Null
    New-Item -Path $instPath   -Force | Out-Null
    New-Item -Path $defInstPath -Force | Out-Null

    Set-ItemProperty -Path $svcPath -Name 'Type'         -Value 2  -Type DWord
    Set-ItemProperty -Path $svcPath -Name 'Start'        -Value 3  -Type DWord
    Set-ItemProperty -Path $svcPath -Name 'ErrorControl' -Value 1  -Type DWord
    Set-ItemProperty -Path $svcPath -Name 'ImagePath'    -Value "\SystemRoot\System32\drivers\$SysFile" -Type ExpandString
    Set-ItemProperty -Path $svcPath -Name 'DisplayName'  -Value 'RansomShield File System Minifilter Driver' -Type String
    Set-ItemProperty -Path $svcPath -Name 'Group'        -Value 'FSFilter Activity Monitor' -Type String
    Set-ItemProperty -Path $svcPath -Name 'SupportedFeatures' -Value 3 -Type DWord

    Set-ItemProperty -Path $instPath    -Name 'DefaultInstance' -Value $DriverName  -Type String
    Set-ItemProperty -Path $defInstPath -Name 'Altitude'        -Value $DriverAlt   -Type String
    Set-ItemProperty -Path $defInstPath -Name 'Flags'           -Value 1            -Type DWord

    Write-Ok 'Service registry entries written.'

    # ── Step 4: load the driver ────────────────────────────────────────────────
    Write-Host '  Loading driver with fltmc ...'
    $loadOut = fltmc load $DriverName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "fltmc load failed: $loadOut"
        Show-CodeIntegrityLog
        Write-Host @'

  Common causes:
    - Test signing not enabled (bcdedit /set testsigning on + reboot)
    - Driver binary is not code-signed (even a self-signed test cert is needed
      when Secure Boot is active — see WDK signtool docs)
    - Memory Integrity (HVCI) is enabled — must be disabled for test-signed drivers
'@ -ForegroundColor Yellow
        exit 1
    }
    Write-Ok "Driver loaded: $loadOut"

    Show-Status
}

# ─── Uninstall ────────────────────────────────────────────────────────────────
function Invoke-Uninstall {
    Write-Header 'Uninstalling driver'

    # Unload if running
    $running = Get-DriverStatus
    if ($running) {
        Write-Host '  Unloading driver ...'
        fltmc unload $DriverName 2>&1 | Out-Null
        Start-Sleep -Seconds 1
        Write-Ok 'Driver unloaded.'
    } else {
        Write-Warn 'Driver was not loaded.'
    }

    # Stop and delete the service
    $svc = Get-Service -Name $DriverName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $DriverName -Force -ErrorAction SilentlyContinue
        }
        sc.exe delete $DriverName | Out-Null
        Write-Ok 'Service deleted.'
    } else {
        Write-Warn 'Service was not registered — nothing to delete.'
    }

    # Remove the binary from system32\drivers if it's ours
    $sysInstalled = "$env:SystemRoot\system32\drivers\$SysFile"
    if (Test-Path $sysInstalled) {
        Remove-Item $sysInstalled -Force
        Write-Ok "Removed $sysInstalled"
    }

    Write-Ok 'Uninstall complete.'
}

# ─── Entry point ──────────────────────────────────────────────────────────────
Write-Host "`nRansomShield Deployment Script" -ForegroundColor White
Write-Host "Action: $Action  |  Configuration: $Configuration" -ForegroundColor DarkGray

switch ($Action) {
    'status' {
        Show-Status
    }
    'build' {
        Invoke-Build
    }
    'install' {
        Assert-TestSigningEnabled
        Assert-HvciDisabled
        if (-not $SkipBuild) { Invoke-Build }
        if (-not $SkipSign)  { Invoke-Sign  }
        Invoke-Install
    }
    'uninstall' {
        Invoke-Uninstall
    }
}
