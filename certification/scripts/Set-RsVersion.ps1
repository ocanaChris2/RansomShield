<#
.SYNOPSIS
    Stamps one version number into every place the driver carries it.

.DESCRIPTION
    RansomShield.sys carries its version in places that must agree:

      kernel\RansomShield.rc        FILEVERSION, PRODUCTVERSION and the
                                    "FileVersion" / "ProductVersion" strings
      RansomShield.inf              DriverVer = <date>,<version>
      RansomShield.Driver.vcxproj   <TimeStamp> (INF stamping in the WDK project)

    (Invoke-PackageDriver.ps1 reads the version back from the INF.)

    This script sets all of them to -Version. The release workflow runs it on
    tag builds (tag v1.2.3 -> 1.2.3.0) before building, so the release binaries
    carry the tag's version. It can also be run locally before committing a
    version bump.

    Each pattern must match exactly once: a format change in any file fails
    the run instead of being silently skipped. Files are edited byte for byte
    (read and written as Latin-1), so only the ASCII version fields change and
    every other byte, line ending and encoding is preserved.

.PARAMETER Version
    Four numeric parts, each 0-65535 (for example 1.2.3.0).

.PARAMETER Date
    DriverVer date. Default: today (UTC).

.EXAMPLE
    pwsh certification\scripts\Set-RsVersion.ps1 -Version 1.2.3.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [datetime]$Date = [datetime]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -match '^(\d{1,5})\.(\d{1,5})\.(\d{1,5})\.(\d{1,5})$') {
    $m = $Matches
    $parts = @(1..4 | ForEach-Object { [int]$m[$_] })
} else {
    throw "Version '$Version' must be four numeric parts, for example 1.2.3.0"
}
if (@($parts | Where-Object { $_ -gt 65535 }).Count -gt 0) {
    throw "Each version part must be 0-65535 (got $Version)"
}

$commaVersion  = $parts -join ','
$dottedVersion = $parts -join '.'
$infDate       = $Date.ToString('MM/dd/yyyy', [Globalization.CultureInfo]::InvariantCulture)
$repoRoot      = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$latin1        = [Text.Encoding]::GetEncoding(28591)   # 1 byte <-> 1 char: lossless round trip

function Update-RsFile {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][object[]]$Replacements    # @{ Pattern = '...'; Value = '...' }
    )

    $path  = Join-Path $repoRoot $RelativePath
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF))) {
        throw "${RelativePath}: UTF-16 files are not supported by this script"
    }

    $text = $latin1.GetString($bytes)
    foreach ($r in $Replacements) {
        $found = [regex]::Matches($text, $r.Pattern).Count
        if ($found -ne 1) {
            throw "${RelativePath}: expected exactly one match for /$($r.Pattern)/, found $found"
        }
        $text = [regex]::Replace($text, $r.Pattern, $r.Value)
    }

    [IO.File]::WriteAllBytes($path, $latin1.GetBytes($text))
    Write-Host "  stamped $RelativePath -> $dottedVersion"
}

Update-RsFile 'kernel\RansomShield.rc' @(
    @{ Pattern = '(?m)^(\s*FILEVERSION\s+)\d+,\d+,\d+,\d+';    Value = '${1}' + $commaVersion }
    @{ Pattern = '(?m)^(\s*PRODUCTVERSION\s+)\d+,\d+,\d+,\d+'; Value = '${1}' + $commaVersion }
    @{ Pattern = '(VALUE\s+"FileVersion",\s*")[^"]*(")';       Value = '${1}' + $dottedVersion + '${2}' }
    @{ Pattern = '(VALUE\s+"ProductVersion",\s*")[^"]*(")';    Value = '${1}' + $dottedVersion + '${2}' }
)

Update-RsFile 'RansomShield.inf' @(
    @{ Pattern = '(?m)^(DriverVer\s*=\s*)[0-9/]+,[0-9.]+'; Value = '${1}' + "$infDate,$dottedVersion" }
)

Update-RsFile 'RansomShield.Driver.vcxproj' @(
    @{ Pattern = '(<TimeStamp>)[0-9.]+(</TimeStamp>)'; Value = '${1}' + $dottedVersion + '${2}' }
)

Write-Host "Version $dottedVersion stamped (DriverVer date $infDate)."
